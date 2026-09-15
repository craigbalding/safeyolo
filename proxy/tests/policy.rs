use safeyolo_proxy::policy::{Effect, ErrorKind, Format, NetworkRequest, Policy};
use serde_json::{Value, json};

fn request<'a>(host: &'a str, agent: Option<&'a str>, port: u16) -> NetworkRequest<'a> {
    NetworkRequest {
        agent,
        host,
        port: Some(port),
        method: "GET",
        path: "/",
    }
}

fn scenarios() -> Value {
    let default_requests = |hosts: &[&str], agents: &[Value], ports: &[u16]| -> Vec<Value> {
        let mut result = Vec::new();
        for host in hosts {
            for agent in agents {
                for port in ports {
                    result.push(json!({"host":host,"agent":agent,"port":port,"method":"GET","path":"/","now_ms":1000000.0,"consume":false}));
                }
            }
        }
        result
    };
    let hosts = [
        "exact.example",
        "special.example",
        "other.example",
        "sub.example.com",
        "example.com",
        "EXACT.EXAMPLE",
        "UPPER.example",
        "upper.example",
        "a.class.example",
        "b.class.example",
        "d.class.example",
        "2001:db8::1",
        "::ffff:c000:201",
        "::ffff:192.0.2.1",
    ];
    let agents = [
        Value::Null,
        json!("alice"),
        json!("bob"),
        json!("robot-one"),
        json!("ROBOT-one"),
    ];
    let mut budget_requests = Vec::new();
    for (host, agent, port, method, now_ms, consume) in [
        ("limited.example", "alice", 80, "GET", 1000000., false),
        ("limited.example", "alice", 80, "GET", 1000000., true),
        ("limited.example", "bob", 443, "GET", 1000000., true),
        ("limited.example", "alice", 80, "GET", 1000000., true),
        ("other.example", "alice", 80, "GET", 1000000., true),
        ("limited.example", "alice", 80, "CONNECT", 1000000., true),
        ("limited.example", "bob", 80, "CONNECT", 1000000., true),
        ("limited.example", "alice", 80, "CONNECT", 1000000., true),
        ("limited.example", "alice", 80, "GET", 1006000., true),
        ("endpoint.example", "alice", 22, "CONNECT", 1006000., true),
        ("endpoint.example", "bob", 22, "CONNECT", 1006000., true),
        ("endpoint.example", "alice", 22, "CONNECT", 1006000., true),
        ("endpoint.example", "alice", 2222, "CONNECT", 1006000., true),
    ] {
        budget_requests.push(json!({"host":host,"agent":agent,"port":port,"method":method,"path":"/","now_ms":now_ms,"consume":consume}));
    }
    let mut iam_requests = Vec::new();
    for host in [
        "api.example",
        "tie.example",
        "scope.example",
        "other.example",
    ] {
        for method in ["GET", "post", "DELETE"] {
            for path in ["/", "/v1/read", "/v1/delete"] {
                for agent in [Value::Null, json!("alice"), json!("bob")] {
                    iam_requests.push(json!({"host":host,"agent":agent,"port":443,"method":method,"path":path,"now_ms":1000000.,"consume":false}));
                }
            }
        }
    }
    json!([
        {"format":"toml","source":r#"
budget = 100
required = ["network_guard"]
[hosts]
"*" = {egress="prompt"}
"exact.example" = {egress="allow"}
"exact.example:22" = {egress="deny"}
"UPPER.example" = {egress="deny"}
"*.example.com" = {egress="allow"}
"[a-c].class.example" = {egress="deny"}
"[2001:db8::1]:22" = {egress="allow"}
"[::ffff:c000:201]:22" = {egress="allow"}
[agents.alice]
egress = "deny"
[agents.alice.hosts]
"special.example" = {egress="allow"}
"special.example:22" = {egress="prompt"}
[agents."robot-*".hosts]
"*.example.com" = {egress="deny"}
"special.example" = {egress="allow"}
"#,"requests":default_requests(&hosts, &agents, &[22,80,443])},
        {"format":"toml","source":r#"
[hosts]
"*" = {egress="allow"}
"exact.example" = {egress="deny"}
[agents.alice]
egress = "prompt"
[agents.alice.hosts]
"*" = {egress="allow"}
"exact.example" = {egress="allow"}
"#,"requests":default_requests(&["exact.example","other.example"], &agents, &[80])},
        {"format":"toml","source":r#"
budget = 10
[hosts]
"*" = {egress="allow"}
"limited.example" = {rate=1}
"endpoint.example:22" = {rate=1}
"endpoint.example:2222" = {rate=1}
"#,"requests":budget_requests},
        {"format":"json","source":json!({"permissions":[
            {"action":"network:request","resource":"*","effect":"deny"},
            {"action":"network:request","resource":"api.example/*","effect":"allow","condition":{"method":["GET","POST"],"path_prefix":"/v1/","port":[443,8443]}},
            {"action":"network:request","resource":"api.example/*","effect":"prompt","condition":{"method":"DELETE"}},
            {"action":"network:request","resource":"scope.example/*","effect":"allow","condition":{"agent":"alice"}},
            {"action":"network:request","resource":"tie.example/*","effect":"allow"},
            {"action":"network:request","resource":"tie.example/*","effect":"deny"},
            {"action":"network:request","resource":"scope.example/*","effect":"deny","tier":"inferred"}
        ]}).to_string(),"requests":iam_requests},
        {"format":"yaml","source":r#"
global_budget: 100
hosts:
  '*': {egress: deny}
  exact.example: {rate_limit: 10, bypass: [network_guard]}
  '*.example.com': {egress: allow}
agents:
  alice:
    egress: prompt
    hosts:
      'exact.example:22': {egress: allow}
clients:
  'robot-*': {bypass: [network_guard]}
"#,"requests":default_requests(&hosts, &agents, &[22,80])},
        {"format":"json","source":json!({"hosts":{"*":{"egress":"deny"},"exact.example":{"egress":"allow","addons":{"network_guard":{"enabled":false}}}},"addons":{"network_guard":{"enabled":true}}}).to_string(),"requests":default_requests(&["exact.example","other.example"], &agents, &[80])},
        {"format":"yaml","source":r#"
default_host: &host_default {egress: deny}
hosts:
  '*': {egress: prompt}
  exact.example: {<<: *host_default}
  'b?.example': {egress: allow}
  '[!a-c].example': {egress: deny}
"#,"requests":default_requests(&["exact.example","ba.example","bb.example","b.example","d.example","a.example"], &agents, &[80])},
        {"format":"json","source":json!({"hosts":{"*":{"egress":"prompt"},"tie.example":{"rate_limit":10,"rules":[{"action":"network:request","resource":"tie.example/*","effect":"deny","condition":{}}]}}}).to_string(),"requests":default_requests(&["tie.example","other.example"], &agents, &[80])},
        {"format":"yaml","source":r#"
defaults: &defaults
  'a*.example': {egress: deny}
hosts:
  <<: *defaults
  '*b.example': {egress: allow}
"#,"requests":default_requests(&["ab.example","cb.example"], &agents, &[80])}
    ])
}

fn evaluate_scenarios(scenarios: &Value) -> Value {
    Value::Array(scenarios.as_array().unwrap().iter().map(|scenario| {
        let format = match scenario["format"].as_str().unwrap() {"toml" => Format::Toml,"yaml" => Format::Yaml,_=>Format::Json};
        let policy = Policy::parse(scenario["source"].as_str().unwrap(), format).unwrap();
        Value::Array(scenario["requests"].as_array().unwrap().iter().map(|request| {
            let network = NetworkRequest {agent:request["agent"].as_str(), host:request["host"].as_str().unwrap(), port:request["port"].as_u64().map(|port|port as u16), method:request["method"].as_str().unwrap(), path:request["path"].as_str().unwrap()};
            let decision = policy.evaluate(network, request["now_ms"].as_f64().unwrap(), request["consume"].as_bool().unwrap()).unwrap();
            json!({"effect":decision.effect,"budget_remaining":decision.budget_remaining,"enabled":policy.network_guard_enabled(network)})
        }).collect())
    }).collect())
}

#[test]
fn agent_defaults_override_global_exact_hosts_and_endpoints_override_hostwide_rules() {
    let policy = Policy::parse(
        r#"
[hosts]
"*" = {egress="prompt"}
"allowed.example" = {egress="allow"}
"allowed.example:22" = {egress="deny"}
[agents.alice]
egress = "deny"
[agents.alice.hosts]
"only.example:22" = {egress="allow"}
"#,
        Format::Toml,
    )
    .unwrap();
    for (host, agent, port, expected) in [
        ("allowed.example", None, 80, Effect::Allow),
        ("allowed.example", None, 22, Effect::Deny),
        ("allowed.example", Some("alice"), 80, Effect::Deny),
        ("only.example", Some("alice"), 22, Effect::Allow),
        ("only.example", Some("alice"), 443, Effect::Deny),
        ("only.example", Some("bob"), 22, Effect::Prompt),
    ] {
        assert_eq!(
            policy
                .evaluate(request(host, agent, port), 1000000., true)
                .unwrap()
                .effect,
            expected
        );
    }
}

#[test]
fn aggregate_and_host_budgets_are_atomic_shared_and_separate_for_connect() {
    let policy = Policy::parse(
        "budget=100\n[hosts]\n'*'={egress='allow'}\n'limited.example'={rate=1}\n",
        Format::Toml,
    )
    .unwrap();
    let limited = request("limited.example", Some("alice"), 80);
    assert_eq!(
        policy.evaluate(limited, 1000000., false).unwrap().effect,
        Effect::Allow
    );
    assert_eq!(
        policy.evaluate(limited, 1000000., true).unwrap().effect,
        Effect::Allow
    );
    assert_eq!(
        policy
            .evaluate(request("limited.example", Some("bob"), 443), 1000000., true)
            .unwrap()
            .effect,
        Effect::Allow
    );
    for _ in 0..20 {
        assert_eq!(
            policy.evaluate(limited, 1000000., true).unwrap().effect,
            Effect::BudgetExceeded
        );
    }
    // Rejected host traffic spent none of the remaining aggregate burst.
    for _ in 0..9 {
        assert_eq!(
            policy
                .evaluate(request("other.example", None, 80), 1000000., true)
                .unwrap()
                .effect,
            Effect::Allow
        );
    }
    assert_eq!(
        policy
            .evaluate(request("other.example", None, 80), 1000000., true)
            .unwrap()
            .effect,
        Effect::BudgetExceeded
    );
    assert_eq!(
        policy
            .evaluate(
                NetworkRequest {
                    method: "CONNECT",
                    ..limited
                },
                1000000.,
                true
            )
            .unwrap()
            .effect,
        Effect::Allow
    );
}

#[test]
fn unsupported_network_features_and_invalid_policies_cannot_be_misread_as_allow() {
    for source in [
        "lists={blocked='hosts.txt'}\n[hosts]\n'$blocked'={egress='deny'}",
        "[hosts]\n'x'={egress='allow'}\n[agents.alice.hosts]\n'x'={bypass=['network_guard']}",
    ] {
        assert_eq!(
            Policy::parse(source, Format::Toml).unwrap_err().kind,
            ErrorKind::Unsupported
        );
    }
    let unsupported = json!({"permissions":[{"action":"network:request","resource":"*","effect":"allow","condition":{"future_context":"api:*"}}]}).to_string();
    assert_eq!(
        Policy::parse(&unsupported, Format::Json).unwrap_err().kind,
        ErrorKind::Unsupported
    );
    for source in [
        "[hosts",
        "hosts=3",
        "budget=10\nglobal_budget=10",
        "budget=10\n[hosts]\n'x'={rate=11}",
        "[hosts]\n'x:0'={egress='allow'}",
        "[hosts]\n'x:65536'={egress='allow'}",
        "[hosts]\n'x:22'={egress='allow',allow=['api:*']}",
        "[hosts]\n'x'={rate=true}",
    ] {
        assert!(Policy::parse(source, Format::Toml).is_err(), "{source}");
    }
    assert_eq!(
        Policy::parse("", Format::Toml)
            .unwrap()
            .evaluate(request("x", None, 80), 0., true)
            .unwrap()
            .effect,
        Effect::Deny
    );
}

#[test]
fn case_and_apex_behavior_remain_explicit_compatibility_discrepancies() {
    let policy = Policy::parse("[hosts]\n'*'={egress='prompt'}\n'Exact.example'={egress='deny'}\n'*.example.com'={egress='allow'}",Format::Toml).unwrap();
    assert_eq!(
        policy
            .evaluate(request("Exact.example", None, 80), 0., true)
            .unwrap()
            .effect,
        Effect::Deny
    );
    assert_eq!(
        policy
            .evaluate(request("exact.example", None, 80), 0., true)
            .unwrap()
            .effect,
        Effect::Prompt
    );
    assert_eq!(
        policy
            .evaluate(request("sub.example.com", None, 80), 0., true)
            .unwrap()
            .effect,
        Effect::Allow
    );
    assert_eq!(
        policy
            .evaluate(request("example.com", None, 80), 0., true)
            .unwrap()
            .effect,
        Effect::Prompt
    );
}

#[test]
fn from_path_merges_sibling_addon_defaults_without_overwriting_policy() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.toml");
    std::fs::write(&path, "[hosts]\n'*'={egress='allow'}").unwrap();
    std::fs::write(
        directory.path().join("addons.yaml"),
        "addons:\n  network_guard: {enabled: false}\n",
    )
    .unwrap();
    let policy = Policy::from_path(&path).unwrap();
    assert!(!policy.network_guard_enabled(request("x", None, 80)));
    std::fs::write(
        &path,
        "[hosts]\n'*'={egress='allow'}\n[addons.network_guard]\nenabled=true",
    )
    .unwrap();
    assert!(
        Policy::from_path(&path)
            .unwrap()
            .network_guard_enabled(request("x", None, 80))
    );
}

#[test]
fn concurrent_requests_cannot_double_spend_a_budget() {
    use std::sync::{Arc, Barrier};
    let policy = Arc::new(Policy::parse("[hosts]\n'*'={rate=1}", Format::Toml).unwrap());
    let barrier = Arc::new(Barrier::new(24));
    let workers: Vec<_> = (0..24)
        .map(|_| {
            let (policy, barrier) = (policy.clone(), barrier.clone());
            std::thread::spawn(move || {
                barrier.wait();
                policy
                    .evaluate(request("same.example", Some("alice"), 80), 1000000., true)
                    .unwrap()
                    .effect
            })
        })
        .collect();
    let allowed = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .filter(|effect| *effect == Effect::Allow)
        .count();
    assert_eq!(allowed, 2, "GCRA admits initial plus one burst at rate1");
}

#[test]
fn schema_lists_and_permission_tiers_are_not_silently_coerced() {
    for document in [
        json!({"required":"network_guard","hosts":{"x.example":{"egress":"allow"}}}),
        json!({"hosts":{"x.example":{"egress":"allow","bypass":"network_guard"}}}),
        json!({"clients":{"alice":{"bypass":"network_guard"}},"hosts":{"x.example":{"egress":"allow"}}}),
        json!({"domains":{"x.example":{"bypass":"network_guard"}},"permissions":[{"action":"network:request","resource":"*","effect":"allow"}]}),
        json!({"required":[true],"hosts":{"x.example":{"egress":"allow"}}}),
        json!({"permissions":[{"action":"network:request","resource":"*","effect":"allow","tier":3}]}),
        json!({"permissions":[{"action":"network:request","resource":"*","effect":"allow","tier":null}]}),
    ] {
        assert_eq!(
            Policy::parse(&document.to_string(), Format::Json)
                .unwrap_err()
                .kind,
            ErrorKind::Invalid,
            "{document}"
        );
    }
    for method in [json!("GET"), json!(["GET"])] {
        let document = json!({"permissions":[{"action":"network:request","resource":"*","effect":"allow","condition":{"method":method}}]});
        assert_eq!(
            Policy::parse(&document.to_string(), Format::Json)
                .unwrap()
                .evaluate(request("x.example", None, 80), 0., false)
                .unwrap()
                .effect,
            Effect::Allow
        );
    }
}

#[test]
fn expiry_is_scoped_to_agent_and_port_and_applied_only_at_reload() {
    let source = r#"
[hosts]
'*'={egress='allow'}
'global.example:22'={egress='deny',expires=2026-01-01T00:00:00Z}
'invalid.example'={egress='deny',expires='not-a-date'}
'date.example'={egress='deny',expires=2026-01-01}
'stringdate.example'={egress='deny',expires='2026-01-01'}
[agents.alice.hosts]
'agent.example:22'={egress='deny',expires='2026-01-01T00:00:00Z'}
'agent.example:443'={egress='prompt'}
"#;
    let boundary = 1_767_225_600_000.;
    let before = Policy::parse_at(source, Format::Toml, boundary - 1.).unwrap();
    assert_eq!(
        before
            .evaluate(
                request("agent.example", Some("alice"), 22),
                boundary + 1.,
                false
            )
            .unwrap()
            .effect,
        Effect::Deny,
        "evaluation does not promise a timer-driven reload"
    );
    let after = before
        .reload_from_source_at(source, Format::Toml, boundary)
        .unwrap();
    for (host, agent, port, effect) in [
        ("global.example", None, 22, Effect::Allow),
        ("agent.example", Some("alice"), 22, Effect::Allow),
        ("agent.example", Some("alice"), 443, Effect::Prompt),
        ("agent.example", Some("bob"), 443, Effect::Allow),
        ("invalid.example", None, 443, Effect::Deny),
        ("date.example", None, 443, Effect::Deny),
        ("stringdate.example", None, 443, Effect::Allow),
    ] {
        assert_eq!(
            after
                .evaluate(request(host, agent, port), boundary, false)
                .unwrap()
                .effect,
            effect,
            "{host}:{port} {agent:?}"
        );
    }
}

#[test]
fn successful_reload_and_old_snapshots_share_budget_charges() {
    let source = "budget=10\n[hosts]\n'limited.example'={rate=1}";
    let original = Policy::parse(source, Format::Toml).unwrap();
    let network = request("limited.example", Some("alice"), 80);
    assert_eq!(
        original.evaluate(network, 1000000., true).unwrap().effect,
        Effect::Allow
    );
    let reloaded = original
        .reload_from_source_at(source, Format::Toml, 1000000.)
        .unwrap();
    assert_eq!(
        reloaded.evaluate(network, 1000000., true).unwrap().effect,
        Effect::Allow
    );
    assert_eq!(
        original.evaluate(network, 1000000., true).unwrap().effect,
        Effect::BudgetExceeded
    );
    assert_eq!(
        reloaded.evaluate(network, 1000000., true).unwrap().effect,
        Effect::BudgetExceeded
    );
    assert!(
        reloaded
            .reload_from_source_at("hosts=7", Format::Toml, 1000000.)
            .is_err()
    );
    assert_eq!(
        reloaded.evaluate(network, 1000000., true).unwrap().effect,
        Effect::BudgetExceeded
    );
}

#[test]
fn file_reload_keeps_addon_defaults_and_budget_counters() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.toml");
    std::fs::write(&path, "budget=1\n[hosts]\n'*'={egress='allow'}").unwrap();
    std::fs::write(
        path.with_file_name("addons.yaml"),
        "addons:\n  network_guard: {enabled: false}\n",
    )
    .unwrap();
    let original = Policy::from_path_at(&path, 1000000.).unwrap();
    let network = request("x.example", None, 80);
    for _ in 0..2 {
        assert_eq!(
            original.evaluate(network, 1000000., true).unwrap().effect,
            Effect::Allow
        );
    }
    let reloaded = original.reload_from_path_at(&path, 1000000.).unwrap();
    assert!(!reloaded.network_guard_enabled(network));
    assert_eq!(
        reloaded.evaluate(network, 1000000., true).unwrap().effect,
        Effect::BudgetExceeded
    );
}

#[test]
fn authored_datetime_marker_objects_never_expire_a_denial() {
    for (format,source) in [
        (Format::Json,json!({"hosts":{"*":{"egress":"allow"},"x":{"egress":"deny","expires":{"$__toml_private_datetime":"2000-01-01T00:00:00Z"}}}}).to_string()),
        (Format::Toml,"[hosts]\n'*'={egress='allow'}\n'x'={egress='deny',expires={'$__toml_private_datetime'='2000-01-01T00:00:00Z'}}".into()),
    ] {
        assert_eq!(Policy::parse(&source,format).unwrap().evaluate(request("x",None,443),0.,false).unwrap().effect,Effect::Deny);
    }
    for (value, effect) in [
        ("2026-01-01", Effect::Deny),
        ("'2026-01-01'", Effect::Allow),
    ] {
        let source =
            format!("hosts:\n  '*': {{egress: allow}}\n  x: {{egress: deny, expires: {value}}}\n");
        assert_eq!(
            Policy::parse(&source, Format::Yaml)
                .unwrap()
                .evaluate(request("x", None, 80), 0., false)
                .unwrap()
                .effect,
            effect
        );
    }
    let yaml =
        "hosts:\n  '*': {egress: allow}\n  x: {egress: deny, expires: 2000-01-01T00:00:00Z}\n";
    assert_eq!(
        Policy::parse(yaml, Format::Yaml)
            .unwrap()
            .evaluate(request("x", None, 443), 0., false)
            .unwrap()
            .effect,
        Effect::Allow
    );
}

#[test]
#[ignore = "historical Python oracle; run with SAFEYOLO_POLICY_PYTHON pointing at the baseline environment"]
fn differential_matrix_matches_existing_python_policy_engine() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let scenarios = scenarios();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let python = std::env::var_os("SAFEYOLO_POLICY_PYTHON")
        .expect("set SAFEYOLO_POLICY_PYTHON to the existing Python environment");
    let script = r#"
import json, pathlib, sys, tempfile
from unittest.mock import patch
from safeyolo.policy.engine import PolicyEngine
from safeyolo.policy.compiler import compile_policy
from safeyolo.policy.models import UnifiedPolicy
from pydantic import ValidationError
invalid_documents=[
    {'hosts':{'x.example':{'egress':'allow','bypass':'network_guard'}}},
    {'hosts':{'x.example':{'egress':'allow'}},'clients':{'alice':{'bypass':'network_guard'}}},
    {'hosts':{'x.example':{'egress':'allow'}},'required':'network_guard'},
    *[{'permissions':[{'action':'network:request','resource':'*','effect':'allow','tier':tier}]} for tier in (None,3)],
]
for document in invalid_documents:
    try: UnifiedPolicy.model_validate(compile_policy(document) if 'hosts' in document else document)
    except ValidationError: pass
    else: raise AssertionError(f'Python unexpectedly accepted {document}')
# Regression evidence for the currently ineffective agent-host bypass, which
# native parsing explicitly refuses until its intended contract is resolved.
compiled = compile_policy({'hosts': {'x.example': {'egress': 'allow'}}, 'agents': {'alice': {'hosts': {'x.example': {'bypass': ['network_guard']}}}}})
assert not compiled.get('domains')
outputs = []
for scenario in json.load(sys.stdin):
    with tempfile.TemporaryDirectory() as directory:
        path = pathlib.Path(directory) / ('policy.' + scenario['format'])
        path.write_text(scenario['source'])
        engine = PolicyEngine(baseline_path=path)
        engine._loader.stop_watcher()
        decisions = []
        for request in scenario['requests']:
            with patch('safeyolo.policy.budget_tracker.time.time', return_value=request['now_ms']/1000):
                decision = engine.evaluate_request(request['host'],path=request['path'],method=request['method'],agent=request['agent'],port=request['port'],consume_budget=request['consume'])
                enabled = engine.is_addon_enabled('network_guard',request['host'],request['agent'])
                decisions.append({'effect':decision.effect,'budget_remaining':decision.budget_remaining,'enabled':enabled})
        outputs.append(decisions)
        engine.done()
json.dump(outputs,sys.stdout)
"#;
    let mut child = Command::new(python)
        .arg("-c")
        .arg(script)
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
        .write_all(serde_json::to_string(&scenarios).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Value = serde_json::from_slice(&output.stdout).unwrap();
    let actual = evaluate_scenarios(&scenarios);
    assert_eq!(
        actual.as_array().unwrap().len(),
        expected.as_array().unwrap().len()
    );
    let count: usize = scenarios
        .as_array()
        .unwrap()
        .iter()
        .map(|scenario| scenario["requests"].as_array().unwrap().len())
        .sum();
    eprintln!(
        "Compared {count} network decisions across {} documents against the existing Python engine",
        scenarios.as_array().unwrap().len()
    );
    for (scenario_index, (actual, expected)) in actual
        .as_array()
        .unwrap()
        .iter()
        .zip(expected.as_array().unwrap())
        .enumerate()
    {
        assert_eq!(
            actual.as_array().unwrap().len(),
            expected.as_array().unwrap().len()
        );
        for (request_index, (actual, expected)) in actual
            .as_array()
            .unwrap()
            .iter()
            .zip(expected.as_array().unwrap())
            .enumerate()
        {
            assert_eq!(
                actual, expected,
                "scenario {scenario_index},request {}",
                scenarios[scenario_index]["requests"][request_index]
            );
        }
    }
}

#[test]
fn tasks_replace_exact_candidates_but_union_simple_rules_and_keep_baseline_ceiling() {
    let baseline = json!({"budgets":{"network:request":1},"permissions":[
        {"action":"network:request","resource":"*","effect":"prompt"},
        {"action":"network:request","resource":"simple.example/*","effect":"deny"},
        {"action":"network:request","resource":"conditional.example/*","effect":"deny","condition":{"port":443}}
    ]});
    let policy = Policy::parse(&baseline.to_string(), Format::Json).unwrap();
    let task = json!({"budgets":{"network:request":1000},"permissions":[
        {"action":"network:request","resource":"simple.example/*","effect":"allow"},
        {"action":"network:request","resource":"conditional.example/*","effect":"allow","condition":{"method":"POST"}},
        {"action":"network:request","resource":"*/*","effect":"allow"}
    ]});
    let active = policy
        .with_task_source(&task.to_string(), Format::Json)
        .unwrap();
    assert_eq!(
        active
            .evaluate(request("simple.example", None, 443), 0., false)
            .unwrap()
            .effect,
        Effect::Deny
    );
    assert_eq!(
        active
            .evaluate(request("conditional.example", None, 443), 0., false)
            .unwrap()
            .effect,
        Effect::Allow,
        "task exact entry hides baseline even with unmatched method; task wildcard then allows"
    );
    for _ in 0..2 {
        assert_eq!(
            active
                .evaluate(request("new.example", None, 443), 0., true)
                .unwrap()
                .effect,
            Effect::Allow
        );
    }
    assert_eq!(
        active
            .evaluate(request("new.example", None, 443), 0., true)
            .unwrap()
            .effect,
        Effect::BudgetExceeded,
        "task cannot raise baseline global ceiling"
    );
    assert_eq!(
        active
            .without_task()
            .evaluate(request("conditional.example", None, 443), 0., false)
            .unwrap()
            .effect,
        Effect::Deny
    );
}

#[test]
fn file_lists_keep_explicit_hosts_first_list_priority_and_last_good_state() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.toml");
    let source = "[lists]\nblocked='blocked.txt'\nallowed='allowed.txt'\n[hosts]\n'*'={egress='prompt'}\n'$blocked'={egress='deny'}\n'$allowed'={egress='allow'}\n'explicit.example'={egress='allow'}\n";
    std::fs::write(&path, source).unwrap();
    std::fs::write(directory.path().join("blocked.txt"),"# comment\n0.0.0.0 explicit.example\n127.0.0.1 blocked.example\n::1 overlap.example\nlocalhost.localdomain\nno-dot\nblocked.example\n").unwrap();
    std::fs::write(
        directory.path().join("allowed.txt"),
        "overlap.example\nallowed.example\n",
    )
    .unwrap();
    let original = Policy::from_path(&path).unwrap();
    for (host, effect) in [
        ("explicit.example", Effect::Allow),
        ("blocked.example", Effect::Deny),
        ("overlap.example", Effect::Deny),
        ("allowed.example", Effect::Allow),
    ] {
        assert_eq!(
            original
                .evaluate(request(host, None, 443), 0., false)
                .unwrap()
                .effect,
            effect
        );
    }
    std::fs::write(directory.path().join("blocked.txt"), "new.example\n").unwrap();
    let reloaded = original.reload_from_path_at(&path, 0.).unwrap();
    assert_eq!(
        reloaded
            .evaluate(request("blocked.example", None, 443), 0., false)
            .unwrap()
            .effect,
        Effect::Prompt
    );
    assert_eq!(
        reloaded
            .evaluate(request("overlap.example", None, 443), 0., false)
            .unwrap()
            .effect,
        Effect::Allow
    );
    std::fs::remove_file(directory.path().join("blocked.txt")).unwrap();
    assert_eq!(
        reloaded.reload_from_path_at(&path, 0.).unwrap_err().kind,
        ErrorKind::Read
    );
    assert_eq!(
        reloaded
            .evaluate(request("new.example", None, 443), 0., false)
            .unwrap()
            .effect,
        Effect::Deny
    );
    std::fs::write(
        &path,
        source.replace("blocked.txt", "https://lists.example/blocked.txt"),
    )
    .unwrap();
    assert_eq!(
        Policy::from_path(&path).unwrap_err().kind,
        ErrorKind::Read,
        "URL-looking list values are local filenames, with no network fetch"
    );
}

#[test]
fn expiry_precedes_list_expansion_and_addon_defaults_and_task_reload_is_independent() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.toml");
    std::fs::write(&path,"[lists]\nold='missing.txt'\n[hosts]\n'*'={egress='prompt'}\n'$old'={egress='deny',expires='2000-01-01'}\n").unwrap();
    assert_eq!(
        Policy::from_path(&path)
            .unwrap()
            .evaluate(request("x", None, 443), 0., false)
            .unwrap()
            .effect,
        Effect::Prompt
    );
    std::fs::write(&path, "").unwrap();
    std::fs::write(
        path.with_file_name("addons.yaml"),
        "hosts:\n  x: {egress: deny, expires: '2000-01-01'}\n",
    )
    .unwrap();
    assert_eq!(
        Policy::from_path(&path)
            .unwrap()
            .evaluate(request("x", None, 443), 0., false)
            .unwrap()
            .effect,
        Effect::Deny,
        "sibling defaults are merged after the expiry pass"
    );
    std::fs::remove_file(path.with_file_name("addons.yaml")).unwrap();
    let task_path = directory.path().join("task.json");
    std::fs::write(&task_path,json!({"permissions":[{"action":"network:request","resource":"task.example/*","effect":"allow"}]}).to_string()).unwrap();
    let policy = Policy::from_path(&path)
        .unwrap()
        .with_task_path(&task_path)
        .unwrap();
    std::fs::write(&path, "[hosts]\n'baseline.example'={egress='allow'}").unwrap();
    std::fs::write(&task_path, "malformed").unwrap();
    let replacement = policy.reload_from_path_at(&path, 0.).unwrap();
    assert!(replacement.reload_task().is_err());
    for host in ["task.example", "baseline.example"] {
        assert_eq!(
            replacement
                .evaluate(request(host, None, 443), 0., false)
                .unwrap()
                .effect,
            Effect::Allow,
            "valid baseline load and last valid task survive separate reload outcomes"
        );
    }
}

#[test]
#[ignore = "historical Python oracle; set SAFEYOLO_POLICY_PYTHON to the baseline environment"]
fn advanced_task_condition_list_and_yaml_contracts_match_python() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let base = json!({"budgets":{"network:request":10},"required":["network_guard"],"permissions":[
        {"action":"network:request","resource":"*","effect":"prompt"},
        {"action":"network:request","resource":"simple.example/*","effect":"deny"},
        {"action":"network:request","resource":"shadow.example/*","effect":"deny","condition":{"port":443}},
        {"action":"network:request","resource":"agent.example/*","effect":"allow","condition":{"agent":"alice"}},
        {"action":"network:request","resource":"*.example/*","effect":"deny"}
    ]});
    let tasks = json!([
        null,
        {"budgets":{"network:request":1000},"addons":{"network_guard":{"enabled":false}},"permissions":[
            {"action":"network:request","resource":"simple.example/*","effect":"allow"},
            {"action":"network:request","resource":"shadow.example/*","effect":"allow","condition":{"method":"POST"}},
            {"action":"network:request","resource":"agent.example/*","effect":"deny","condition":{"port":80}},
            {"action":"network:request","resource":"*/*","effect":"allow"}
        ]},
        {"budgets":{"network:request":1},"permissions":[
            {"action":"network:request","resource":"shadow.example/*","effect":"allow","tier":"inferred"},
            {"action":"network:request","resource":"*","effect":"allow"}
        ]},
        {"hosts":{"*":{"egress":"allow"}},"clients":{"bob":{"bypass":["network_guard"]}},"domains":{"agent.example":{"bypass":["network_guard"]}}},
        null
    ]);
    let mut requests = Vec::new();
    for host in [
        "simple.example",
        "shadow.example",
        "agent.example",
        "other.example",
        "elsewhere.test",
    ] {
        for agent in [None, Some("alice"), Some("bob")] {
            for port in [80, 443] {
                for method in ["GET", "POST"] {
                    requests.push(json!({"host":host,"agent":agent,"port":port,"method":method}));
                }
            }
        }
    }
    let conditions = json!([
        {"credential":":*"},{"credential":"api:*"},{"credential":"hmac:x"},{"credential":[":x","other"]},
        {"content_type":""},{"content_type":"application/json"},{"tactics":[]},{"tactics":["x"]},{"enables":[]},{"enables":["x"]},
        {"irreversible":false},{"irreversible":true},{"irreversible":0},{"irreversible":"no"},{"irreversible":"true"},{"account":""},{"account":["billing",""]},{"account":"billing"},
        {"service":"*"},{"service":"api"},{"capability":"*"},{"capability":"?"},
        {"credential":null,"account":null},{"account":"","irreversible":true}
    ]);
    let yaml_expiries = [
        "2000-01-01",
        "'2000-01-01'",
        "2000-1-1 0:00:00Z",
        "2000-01-01T00:00:00Z",
        "!!timestamp '2000-01-01'",
        "!!str 2000-01-01",
        "!!timestamp '2000-1-1 0:00:00 +1'",
        "'broken'",
    ];
    let input = json!({"base":base,"tasks":tasks,"requests":requests,"conditions":conditions,"yaml_expiries":yaml_expiries});
    let script = r#"
import json,pathlib,sys,tempfile
from unittest.mock import patch
from safeyolo.policy.engine import PolicyEngine
data=json.load(sys.stdin);outputs={}
def evaluate(engine,request):
    with patch('safeyolo.policy.budget_tracker.time.time',return_value=1000):
        decision=engine.evaluate_request(request['host'],method=request.get('method','GET'),agent=request.get('agent'),port=request.get('port',443),consume_budget=False)
    return {'effect':decision.effect,'remaining':decision.budget_remaining,'enabled':engine.is_addon_enabled('network_guard',request['host'],request.get('agent'))}
with tempfile.TemporaryDirectory() as directory:
    root=pathlib.Path(directory);path=root/'policy.json';path.write_text(json.dumps(data['base']))
    engine=PolicyEngine(baseline_path=path);engine._loader.stop_watcher();layers=[]
    for task in data['tasks']:
        if task is None: engine.clear_task_policy()
        else:
            task_path=root/'task.json';task_path.write_text(json.dumps(task));assert engine.load_task_policy(task_path)
        layers.append([evaluate(engine,r) for r in data['requests']])
    outputs['tasks']=layers;engine.done()
    rules=[{'action':'network:request','resource':'*','effect':'prompt'}]+[{'action':'network:request','resource':f'c{i}.test/*','effect':'allow','condition':condition} for i,condition in enumerate(data['conditions'])]
    path.write_text(json.dumps({'permissions':rules}));engine=PolicyEngine(baseline_path=path);engine._loader.stop_watcher()
    outputs['conditions']=[evaluate(engine,{'host':f'c{i}.test'}) for i in range(len(data['conditions']))];engine.done()
    expiry=[]
    for value in data['yaml_expiries']:
        path=root/'policy.yaml';path.write_text("hosts:\n  '*': {egress: allow}\n  x: {egress: deny, expires: "+value+"}\n")
        engine=PolicyEngine(baseline_path=path);engine._loader.stop_watcher();expiry.append(evaluate(engine,{'host':'x'}));engine.done()
    outputs['expiry']=expiry
    path=root/'lists.toml';path.write_text("[lists]\nfirst='first.txt'\nsecond='second.txt'\n[hosts]\n'*'={egress='prompt'}\n'$first'={egress='deny'}\n'$second'={egress='allow'}\n'explicit.test'={egress='allow'}\n")
    (root/'first.txt').write_text('# comment\n0.0.0.0 explicit.test\n::1 shared.test\nblocked.test\nblocked.test\nlocalhost.localdomain\n')
    (root/'second.txt').write_text('shared.test\nallowed.test\n')
    engine=PolicyEngine(baseline_path=path);engine._loader.stop_watcher()
    list_hosts=['explicit.test','shared.test','blocked.test','allowed.test','new.test'];states=[]
    states.append([evaluate(engine,{'host':host}) for host in list_hosts])
    (root/'first.txt').write_text('new.test\n');assert engine._loader.reload()
    states.append([evaluate(engine,{'host':host}) for host in list_hosts])
    (root/'first.txt').unlink();assert not engine._loader.reload()
    states.append([evaluate(engine,{'host':host}) for host in list_hosts]);outputs['lists']=states;engine.done()
json.dump(outputs,sys.stdout)
"#;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let mut child = Command::new(
        std::env::var_os("SAFEYOLO_POLICY_PYTHON").expect("set SAFEYOLO_POLICY_PYTHON"),
    )
    .arg("-c")
    .arg(script)
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
    let python: Value = serde_json::from_slice(&output.stdout).unwrap();
    let evaluate = |policy: &Policy, query: &Value| {
        let request = NetworkRequest {
            host: query["host"].as_str().unwrap(),
            agent: query["agent"].as_str(),
            port: Some(query["port"].as_u64().unwrap_or(443) as u16),
            method: query["method"].as_str().unwrap_or("GET"),
            path: "/",
        };
        let decision = policy.evaluate(request, 1_000_000., false).unwrap();
        json!({"effect":decision.effect,"remaining":decision.budget_remaining,"enabled":policy.network_guard_enabled(request)})
    };
    let baseline = Policy::parse(&base.to_string(), Format::Json).unwrap();
    let mut layers = Vec::new();
    for task in tasks.as_array().unwrap() {
        let policy = if task.is_null() {
            baseline.without_task()
        } else {
            baseline
                .with_task_source(&task.to_string(), Format::Json)
                .unwrap()
        };
        layers.push(
            requests
                .iter()
                .map(|query| evaluate(&policy, query))
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(json!(layers), python["tasks"]);
    let mut rules = vec![json!({"action":"network:request","resource":"*","effect":"prompt"})];
    for (index, condition) in conditions.as_array().unwrap().iter().enumerate() {
        rules.push(json!({"action":"network:request","resource":format!("c{index}.test/*"),"effect":"allow","condition":condition}));
    }
    let policy = Policy::parse(&json!({"permissions":rules}).to_string(), Format::Json).unwrap();
    let decisions: Vec<_> = (0..conditions.as_array().unwrap().len())
        .map(|index| evaluate(&policy, &json!({"host":format!("c{index}.test")})))
        .collect();
    assert_eq!(json!(decisions), python["conditions"]);
    let expiry: Vec<_> = yaml_expiries
        .iter()
        .map(|value| {
            let source = format!(
                "hosts:\n  '*': {{egress: allow}}\n  x: {{egress: deny, expires: {value}}}\n"
            );
            evaluate(
                &Policy::parse(&source, Format::Yaml).unwrap(),
                &json!({"host":"x"}),
            )
        })
        .collect();
    assert_eq!(json!(expiry), python["expiry"]);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("lists.toml");
    std::fs::write(&path,"[lists]\nfirst='first.txt'\nsecond='second.txt'\n[hosts]\n'*'={egress='prompt'}\n'$first'={egress='deny'}\n'$second'={egress='allow'}\n'explicit.test'={egress='allow'}\n").unwrap();
    let first = directory.path().join("first.txt");
    std::fs::write(&first,"# comment\n0.0.0.0 explicit.test\n::1 shared.test\nblocked.test\nblocked.test\nlocalhost.localdomain\n").unwrap();
    std::fs::write(
        directory.path().join("second.txt"),
        "shared.test\nallowed.test\n",
    )
    .unwrap();
    let mut policy = Policy::from_path(&path).unwrap();
    let queries = [
        "explicit.test",
        "shared.test",
        "blocked.test",
        "allowed.test",
        "new.test",
    ];
    let mut states = vec![
        queries
            .iter()
            .map(|host| evaluate(&policy, &json!({"host":host})))
            .collect::<Vec<_>>(),
    ];
    std::fs::write(&first, "new.test\n").unwrap();
    policy = policy.reload_from_path_at(&path, 1_000_000.).unwrap();
    states.push(
        queries
            .iter()
            .map(|host| evaluate(&policy, &json!({"host":host})))
            .collect(),
    );
    std::fs::remove_file(first).unwrap();
    assert!(policy.reload_from_path_at(&path, 1_000_000.).is_err());
    states.push(
        queries
            .iter()
            .map(|host| evaluate(&policy, &json!({"host":host})))
            .collect(),
    );
    assert_eq!(json!(states), python["lists"]);
    eprintln!(
        "Advanced Python oracle: {} layered requests, {} default-context conditions, {} YAML expiry cases, {} list reload decisions",
        requests.len() * tasks.as_array().unwrap().len(),
        conditions.as_array().unwrap().len(),
        yaml_expiries.len(),
        queries.len() * states.len()
    );
}
