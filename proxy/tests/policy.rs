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
    (root/'first.txt').write_text('# comment\n0.0.0.0 explicit.test\n::1 shared.test\nblocked.test\nblocked.test\nlocalhost.localdomain\n\x1fleading.test\x1f\n0.0.0.0\x1fprefixed.test\n')
    (root/'second.txt').write_text('shared.test\nallowed.test\n')
    engine=PolicyEngine(baseline_path=path);engine._loader.stop_watcher()
    list_hosts=['explicit.test','shared.test','blocked.test','allowed.test','new.test','leading.test','prefixed.test'];states=[]
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
    std::fs::write(&first,"# comment\n0.0.0.0 explicit.test\n::1 shared.test\nblocked.test\nblocked.test\nlocalhost.localdomain\n\u{1f}leading.test\u{1f}\n0.0.0.0\u{1f}prefixed.test\n").unwrap();
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
        "leading.test",
        "prefixed.test",
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

fn credential<'a>(
    destination: &'a str,
    kind: &'a str,
    hmac: Option<&'a str>,
) -> safeyolo_proxy::policy::CredentialRequest<'a> {
    safeyolo_proxy::policy::CredentialRequest {
        destination,
        credential_type: kind,
        credential_hmac: hmac,
        path: "/v1/read",
    }
}

fn gateway<'a>(
    agent: &'a str,
    method: &'a str,
    path: &'a str,
) -> safeyolo_proxy::policy::GatewayRequest<'a> {
    safeyolo_proxy::policy::GatewayRequest {
        service: "forge",
        capability: "reader",
        agent,
        method,
        path,
    }
}

#[test]
fn host_credentials_use_type_or_exact_hmac_and_do_not_invent_agent_context() {
    let policy = Policy::parse(
        r#"
[hosts.'*']
unknown_creds = 'deny'
[hosts.'api.example']
allow = ['OpenAI:*', 'hmac:exact']
[agents.alice.hosts.'agent.example']
allow = ['openai:*']
"#,
        Format::Toml,
    )
    .unwrap();
    for (host, kind, hmac, effect) in [
        ("api.example", "openai", None, Effect::Allow),
        ("api.example", "other", Some("exact"), Effect::Allow),
        ("api.example", "other", Some("EXACT"), Effect::Deny),
        ("other.example", "openai", None, Effect::Deny),
        ("agent.example", "openai", None, Effect::Deny),
    ] {
        assert_eq!(
            policy
                .evaluate_credential(credential(host, kind, hmac), 0.)
                .unwrap()
                .effect,
            effect
        );
    }
    // '*' credentials lists do not create a global credential allow rule.
    let wildcard = Policy::parse("[hosts.'*']\nallow=['openai:*']", Format::Toml).unwrap();
    assert_eq!(
        wildcard
            .evaluate_credential(credential("any", "openai", None), 0.)
            .unwrap()
            .effect,
        Effect::Prompt
    );
}

#[test]
fn credential_budget_scope_is_atomic_across_hmacs_snapshots_and_action_counters() {
    let source = json!({"budgets":{"credential:use":1,"network:request":1}, "permissions":[
        {"action":"credential:use","resource":"*","effect":"budget","budget":1},
        {"action":"network:request","resource":"*","effect":"budget","budget":1}
    ]})
    .to_string();
    let policy = Policy::parse(&source, Format::Json).unwrap();
    let new = policy
        .reload_from_source_at(&source, Format::Json, 0.)
        .unwrap();
    assert_eq!(
        policy
            .evaluate_credential(credential("api", "openai", Some("first")), 0.)
            .unwrap()
            .effect,
        Effect::Allow
    );
    assert_eq!(
        new.evaluate_credential(credential("api", "openai", Some("second")), 0.)
            .unwrap()
            .effect,
        Effect::Allow
    );
    assert_eq!(
        new.evaluate_credential(credential("api", "openai", None), 0.)
            .unwrap()
            .effect,
        Effect::BudgetExceeded
    );
    assert_eq!(
        new.evaluate_credential(credential("other", "openai", None), 0.)
            .unwrap()
            .effect,
        Effect::Allow
    );
    assert_eq!(
        new.evaluate_credential(credential("api", "anthropic", None), 0.)
            .unwrap()
            .effect,
        Effect::Allow
    );
    assert_eq!(
        new.evaluate(request("api", Some("alice"), 443), 0., true)
            .unwrap()
            .effect,
        Effect::Allow
    );
    assert_eq!(
        new.evaluate(request("api", Some("bob"), 443), 0., true)
            .unwrap()
            .effect,
        Effect::Allow
    );
    assert_eq!(
        new.evaluate(request("api", Some("alice"), 443), 0., true)
            .unwrap()
            .effect,
        Effect::BudgetExceeded
    );
    let concurrent = Policy::parse(&source, Format::Json).unwrap();
    let allowed = std::thread::scope(|scope| {
        let tasks: Vec<_> = (0..32)
            .map(|_| {
                scope.spawn(|| {
                    concurrent
                        .evaluate_credential(credential("api", "openai", None), 0.)
                        .unwrap()
                        .effect
                })
            })
            .collect();
        tasks
            .into_iter()
            .map(|task| task.join().unwrap())
            .filter(|effect| *effect == Effect::Allow)
            .count()
    });
    assert_eq!(allowed, 2);
}

#[test]
fn gateway_generated_routes_replace_only_generated_rules_and_keep_method_context() {
    use safeyolo_proxy::services::CompiledRoute;
    let baseline = Policy::parse(&json!({"permissions":[
        {"action":"gateway:request","resource":"forge:/v1/private","effect":"deny","condition":{"agent":"alice","method":"GET","capability":"reader"}},
        {"action":"gateway:request","resource":"forge:/authored","effect":"allow","condition":{"agent":"alice"}}
    ]}).to_string(), Format::Json).unwrap();
    let routes = [CompiledRoute {
        agent: "alice".into(),
        service: "forge".into(),
        capability: "reader".into(),
        methods: vec!["GET".into()],
        path: "/v1/**".into(),
    }];
    let policy = baseline.with_gateway_routes(&routes);
    assert_eq!(
        policy
            .evaluate_gateway_request(gateway("alice", "GET", "/v1/private"))
            .effect,
        Effect::Deny
    );
    assert_eq!(
        policy
            .evaluate_gateway_request(gateway("alice", "GET", "/v1/open"))
            .effect,
        Effect::Allow
    );
    assert_eq!(
        policy
            .evaluate_gateway_request(gateway("bob", "GET", "/v1/open"))
            .effect,
        Effect::Deny
    );
    assert_eq!(
        policy
            .evaluate_gateway_request(gateway("alice", "POST", "/v1/open"))
            .effect,
        Effect::Deny
    );
    let replacement = policy.with_gateway_routes(&[]);
    assert_eq!(
        replacement
            .evaluate_gateway_request(gateway("alice", "GET", "/v1/open"))
            .effect,
        Effect::Deny
    );
    assert_eq!(
        replacement
            .evaluate_gateway_request(gateway("alice", "GET", "/authored"))
            .effect,
        Effect::Allow
    );
    let wildcard = baseline.with_gateway_routes(&[CompiledRoute {
        methods: vec!["*".into()],
        ..routes[0].clone()
    }]);
    assert_eq!(
        wildcard
            .evaluate_gateway_request(gateway("alice", "GET", "/v1/open"))
            .effect,
        Effect::Deny
    );
    assert_eq!(
        wildcard
            .evaluate_gateway_request(gateway("alice", "*", "/v1/open"))
            .effect,
        Effect::Allow
    );
}

#[test]
fn gateway_conditions_preserve_missing_path_and_uncharged_budget() {
    let path = Policy::parse(&json!({"permissions":[{"action":"gateway:request","resource":"*","effect":"allow","condition":{"path_prefix":"/v1"}}]}).to_string(), Format::Json).unwrap();
    assert_eq!(
        path.evaluate_gateway_request(gateway("alice", "GET", "/v1/read"))
            .effect,
        Effect::Deny
    );
    let budgets = Policy::parse(
        &json!({"permissions":[
            {"action":"gateway:request","resource":"*","effect":"budget","budget":1},
            {"action":"gateway:risky_route","resource":"*","effect":"budget","budget":1}
        ]})
        .to_string(),
        Format::Json,
    )
    .unwrap();
    for _ in 0..5 {
        assert_eq!(
            budgets
                .evaluate_gateway_request(gateway("alice", "GET", "/"))
                .effect,
            Effect::Budget
        );
        let risk = budgets.evaluate_risky_route(safeyolo_proxy::policy::RiskyRouteRequest {
            service: "forge",
            agent: "alice",
            account: "agent",
            tactics: &[],
            enables: &[],
            irreversible: false,
            method: "GET",
            path: "/",
        });
        assert_eq!(risk.effect, Effect::Budget);
        assert_eq!(risk.budget_remaining, None);
    }
    for action in [
        "network:request",
        "credential:use",
        "gateway:risky_route",
        "gateway:request",
    ] {
        assert_eq!(
            Policy::parse(
                &json!({"permissions":[{"action":action,"resource":"*","effect":"warn"}]})
                    .to_string(),
                Format::Json
            )
            .unwrap_err()
            .kind,
            ErrorKind::Invalid
        );
    }
}

fn proxy_action_requests() -> Vec<Value> {
    let mut requests = Vec::new();
    for host in [
        "api.example",
        "sub.example",
        "other",
        "API.EXAMPLE",
        "agent.example",
    ] {
        for kind in ["openai", "OPENAI", "other", ""] {
            for hmac in [Value::Null, json!("exact"), json!("EXACT")] {
                for path in ["/v1/read", "/private"] {
                    requests.push(json!({"kind":"credential", "destination":host,"credential_type":kind,"credential_hmac":hmac,"path":path}));
                }
            }
        }
    }
    for agent in ["alice", "bob", ""] {
        for service in ["forge", "other"] {
            for method in ["GET", "post", "*"] {
                for path in [
                    "/v1/read",
                    "/v1/private",
                    "/v1",
                    "/V1/read",
                    "//v1/%72ead",
                    "/v1/../authored",
                ] {
                    requests.push(json!({"kind":"gateway","service":service,"capability":"reader","agent":agent,"method":method,"path":path}));
                }
                for (account, tactics, enables, irreversible, path) in [
                    ("agent", vec![], vec![], false, "/v1/read"),
                    (
                        "personal",
                        vec!["exfiltration"],
                        vec!["write"],
                        true,
                        "/v1/private",
                    ),
                    ("personal", vec!["discovery"], vec![], false, "/v1/read"),
                ] {
                    requests.push(json!({"kind":"risk","service":service,"agent":agent,"account":account,"tactics":tactics,"enables":enables,"irreversible":irreversible,"method":method,"path":path}));
                }
            }
        }
    }
    requests
}

fn proxy_action_scenarios() -> Vec<Value> {
    let requests = proxy_action_requests();
    let mut scenarios = vec![
        json!({"document":{},"requests":requests}),
        json!({"document":{"hosts":{"*":{"unknown_credentials":"deny"},"api.example":{"credentials":["OpenAI:*","hmac:exact"]},"*.example":{"credentials":"other:*"}},"agents":{"alice":{"hosts":{"agent.example":{"credentials":"*"}}}}},"requests":requests}),
        json!({"document":{"hosts":{"*":{"credentials":["openai:*"],"rules":[{"action":"credential:use","resource":"api.example/*","effect":"deny","condition":{"path_prefix":"/private"}}]}},"gateway":{"risk_appetite":[{"agent":"alice","irreversible":true,"decision":"deny"},{"tactics":["discovery"],"account":"personal","decision":"allow"},{"service":"forge","method":"POST","path_prefix":"/never","decision":"allow"}]}},"requests":requests}),
        json!({"document":{"permissions":[
            {"action":"network:request","resource":"*","effect":"deny"},
            {"action":"credential:use","resource":"api.example/*","effect":"allow","condition":{"credential":"openai:*"}},
            {"action":"credential:use","resource":"*","effect":"deny"},
            {"action":"gateway:risky_route","resource":"*","effect":"deny","condition":{"agent":"alice","irreversible":true}},
            {"action":"gateway:risky_route","resource":"*","effect":"allow","condition":{"method":"GET","path_prefix":"/v1","account":["agent"]}},
            {"action":"gateway:request","resource":"forge:/v1/**","effect":"allow","condition":{"agent":"alice","capability":"reader","method":["GET"]}},
            {"action":"gateway:request","resource":"forge:/v1/private","effect":"deny","condition":{"agent":"alice"}}
        ]},"task":{"permissions":[{"action":"network:request","resource":"api.example/*","effect":"deny","condition":{"method":"GET"}},{"action":"gateway:request","resource":"forge:/*","effect":"prompt","condition":{"agent":"bob"}}]},"requests":requests}),
    ];
    // Every Condition field is exercised against each action's actual supplied
    // context, rather than a reconstructed all-fields context.
    for condition in [
        json!({"credential":"openai:*"}),
        json!({"credential":["hmac:exact", "other:*"]}),
        json!({"credential":"hmac:"}),
        json!({"method":"GET"}),
        json!({"method":"*"}),
        json!({"method":""}),
        json!({"port":443}),
        json!({"path_prefix":"/v1"}),
        json!({"path_prefix":""}),
        json!({"content_type":"json"}),
        json!({"content_type":""}),
        json!({"tactics":["exfiltration"]}),
        json!({"tactics":[]}),
        json!({"enables":["write"]}),
        json!({"irreversible":true}),
        json!({"irreversible":false}),
        json!({"account":["agent", "personal"]}),
        json!({"account":""}),
        json!({"agent":"alice"}),
        json!({"agent":"*"}),
        json!({"agent":""}),
        json!({"service":"f*"}),
        json!({"service":""}),
        json!({"capability":"reader"}),
        json!({"capability":"*"}),
    ] {
        scenarios.push(json!({"document":{"permissions":[
            {"action":"credential:use","resource":"*","effect":"allow","condition":condition},
            {"action":"gateway:risky_route","resource":"*","effect":"deny","condition":condition},
            {"action":"gateway:request","resource":"*","effect":"allow","condition":condition}
        ]},"requests":requests}));
    }
    let service = "schema_version: 1\nname: forge\ncapabilities:\n  reader:\n    routes:\n      - {methods: [GET], path: '/v1/**'}\n      - {methods: ['*'], path: '/authored'}\n";
    scenarios.push(json!({"service_yaml":service,"document":{"hosts":{"*":{"rules":[{"action":"gateway:request","resource":"forge:/v1/private","effect":"deny","condition":{"agent":"alice","capability":"reader","method":["GET"]}}]}},"agents":{"alice":{"services":{"forge":{"capability":"reader"}}}}},"requests":requests}));
    // A task can replace exact candidates only for the same action; inferred
    // entries still shadow the baseline exact key, as in the existing index.
    scenarios.push(json!({"document":{"permissions":[
        {"action":"credential:use","resource":"api.example/*","effect":"allow","condition":{"credential":"openai:*"}},
        {"action":"credential:use","resource":"*","effect":"deny"},
        {"action":"gateway:risky_route","resource":"*","effect":"allow"}
    ]},"task":{"permissions":[
        {"action":"credential:use","resource":"api.example/*","effect":"allow","tier":"inferred","condition":{"path_prefix":"/private"}},
        {"action":"gateway:risky_route","resource":"*","effect":"deny","condition":{"irreversible":true}}
    ]},"requests":requests}));
    for effect in ["allow", "deny", "prompt", "budget"] {
        scenarios.push(
            json!({"document":{"budgets":{"credential:use":1,"network:request":1},"permissions":[
            {"action":"credential:use","resource":"*","effect":effect,"budget":1},
            {"action":"gateway:risky_route","resource":"*","effect":effect,"budget":1},
            {"action":"gateway:request","resource":"*","effect":effect,"budget":1}
        ]},"requests":requests}),
        );
    }
    scenarios
}

fn evaluate_proxy_action(policy: &Policy, request: &Value) -> Value {
    use safeyolo_proxy::policy::{CredentialRequest, GatewayRequest, RiskyRouteRequest};
    let field = |name| request[name].as_str().unwrap();
    let decision = match field("kind") {
        "credential" => policy
            .evaluate_credential(
                CredentialRequest {
                    credential_type: field("credential_type"),
                    destination: field("destination"),
                    path: field("path"),
                    credential_hmac: request["credential_hmac"].as_str(),
                },
                1000000.,
            )
            .unwrap(),
        "gateway" => policy.evaluate_gateway_request(GatewayRequest {
            service: field("service"),
            capability: field("capability"),
            agent: field("agent"),
            method: field("method"),
            path: field("path"),
        }),
        "risk" => policy.evaluate_risky_route(RiskyRouteRequest {
            service: field("service"),
            agent: field("agent"),
            account: field("account"),
            method: field("method"),
            path: field("path"),
            tactics: &serde_json::from_value::<Vec<String>>(request["tactics"].clone()).unwrap(),
            enables: &serde_json::from_value::<Vec<String>>(request["enables"].clone()).unwrap(),
            irreversible: request["irreversible"].as_bool().unwrap(),
        }),
        other => panic!("unknown request kind {other}"),
    };
    json!({"effect":decision.effect,"budget_remaining":decision.budget_remaining})
}

#[test]
#[ignore = "historical Python oracle; set SAFEYOLO_POLICY_PYTHON"]
fn credential_risk_and_gateway_matrix_matches_production_engine() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let scenarios = proxy_action_scenarios();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let script = r#"
import json, pathlib, sys, tempfile
from unittest.mock import patch
from safeyolo.policy.engine import PolicyEngine
from safeyolo.policy.models import Permission
from pydantic import ValidationError
for action in ['network:request','credential:use','gateway:risky_route','gateway:request']:
    try: Permission(action=action,resource='*',effect='warn')
    except ValidationError: pass
    else: raise AssertionError('warn unexpectedly admitted')
outputs=[]
for scenario in json.load(sys.stdin):
    with tempfile.TemporaryDirectory() as directory:
        path=pathlib.Path(directory)/'policy.json'
        path.write_text(json.dumps(scenario['document']))
        registry=None
        if 'service_yaml' in scenario:
            from safeyolo.core.service_loader import ServiceRegistry
            service_dir=pathlib.Path(directory)/'services';service_dir.mkdir()
            (service_dir/'forge.yaml').write_text(scenario['service_yaml'])
            registry=ServiceRegistry(service_dir,builtin_dir=pathlib.Path(directory)/'no-builtins')
            registry.load(strict=True)
        with patch('safeyolo.policy.compiler._get_service_registry',return_value=registry):
            engine=PolicyEngine(baseline_path=path)
        engine._loader.stop_watcher()
        if 'task' in scenario:
            task=pathlib.Path(directory)/'task.json'
            task.write_text(json.dumps(scenario['task']))
            assert engine.load_task_policy(task)
        decisions=[]
        for row in scenario['requests']:
            row=dict(row)
            kind=row.pop('kind')
            with patch('safeyolo.policy.budget_tracker.time.time',return_value=1000):
                if kind=='credential': result=engine.evaluate_credential(**row)
                elif kind=='gateway': result=engine.evaluate_gateway_request(**row)
                else: result=engine.evaluate_risky_route(**row)
            decisions.append({'effect':result.effect,'budget_remaining':result.budget_remaining})
        outputs.append(decisions)
        engine.done()
json.dump(outputs,sys.stdout)
"#;
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
    let input = serde_json::to_vec(&scenarios).unwrap();
    // The finite matrix can exceed a pipe buffer while Python emits its output.
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(&input).unwrap());
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Value = serde_json::from_slice(&output.stdout).unwrap();
    for (index, scenario) in scenarios.iter().enumerate() {
        let mut policy = Policy::parse(&scenario["document"].to_string(), Format::Json).unwrap();
        if let Some(source) = scenario.get("service_yaml").and_then(Value::as_str) {
            use safeyolo_proxy::services::{ServiceDefinition, TokenBinding, compile_routes};
            let service = ServiceDefinition::from_yaml(source).unwrap();
            let routes = compile_routes(
                &service,
                &TokenBinding {
                    token: "synthetic".into(),
                    agent: "alice".into(),
                    service: "forge".into(),
                    capability: "reader".into(),
                    vault_token: String::new(),
                    account: "agent".into(),
                },
                &[],
            );
            policy = policy.with_gateway_routes(&routes);
        }
        if let Some(task) = scenario.get("task") {
            policy = policy
                .with_task_source(&task.to_string(), Format::Json)
                .unwrap();
        }
        for (number, request) in scenario["requests"].as_array().unwrap().iter().enumerate() {
            assert_eq!(
                evaluate_proxy_action(&policy, request),
                expected[index][number],
                "scenario {index}, request {number}: {request}; document {}",
                scenario["document"]
            );
        }
    }
    let count: usize = scenarios
        .iter()
        .map(|scenario| scenario["requests"].as_array().unwrap().len())
        .sum();
    eprintln!(
        "Credential/risk/gateway Python oracle: {count} requests across {} documents",
        scenarios.len()
    );
}

#[test]
fn host_list_python_whitespace_cannot_drop_a_denial() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.toml");
    std::fs::write(
        &path,
        "[lists]\nblocked='blocked.txt'\n[hosts]\n'*'={egress='allow'}\n'$blocked'={egress='deny'}",
    )
    .unwrap();
    // CPython str.isspace's 29 characters, fixed independently of Rust's predicate.
    let whitespace: Vec<_> = "\t\n\u{b}\u{c}\r\u{1c}\u{1d}\u{1e}\u{1f} \u{85}\u{a0}\u{1680}\u{2000}\u{2001}\u{2002}\u{2003}\u{2004}\u{2005}\u{2006}\u{2007}\u{2008}\u{2009}\u{200a}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}".chars().collect();
    let mut data = String::new();
    for (index, character) in whitespace.iter().enumerate() {
        data.push_str(&format!("{character}leading{index}.example{character}\n0.0.0.0{character}prefixed{index}.example\n"));
    }
    std::fs::write(directory.path().join("blocked.txt"), data).unwrap();
    let policy = Policy::from_path(&path).unwrap();
    for index in 0..whitespace.len() {
        for prefix in ["leading", "prefixed"] {
            assert_eq!(
                policy
                    .evaluate(
                        request(&format!("{prefix}{index}.example"), None, 443),
                        0.,
                        false
                    )
                    .unwrap()
                    .effect,
                Effect::Deny
            );
        }
    }
    assert_eq!(
        policy
            .evaluate(request("unlisted.example", None, 443), 0., false)
            .unwrap()
            .effect,
        Effect::Allow
    );
}

#[test]
fn concrete_addon_controls_share_precedence_without_changing_network_wrapper() {
    use safeyolo_proxy::policy::Addon;
    let p=Policy::parse(r#"{"permissions":[],"required":["credential_guard"],"addons":{"credential_guard":{"enabled":false},"network_guard":{"enabled":true},"ignored_addon":7},"domains":{"*.example":{"bypass":["credential_guard"]}},"clients":{"alice":{"bypass":["network_guard"]}}}"#,Format::Json).unwrap();
    assert!(p.is_addon_enabled(Addon::CredentialGuard, Some("api.example"), Some("alice")));
    assert!(!p.is_addon_enabled(Addon::CredentialGuard, Some("other.invalid"), Some("bob")));
    assert!(!p.is_addon_enabled(Addon::NetworkGuard, Some("api.example"), Some("alice")));
    assert_eq!(
        p.network_guard_enabled(request("api.example", Some("alice"), 443)),
        p.is_addon_enabled(Addon::NetworkGuard, Some("api.example"), Some("alice"))
    );
    let task=p.with_task_source(r#"{"addons":{"credential_guard":{"enabled":false},"network_guard":{"enabled":false}}}"#,Format::Json).unwrap();
    assert!(task.is_addon_enabled(Addon::CredentialGuard, Some("other.invalid"), Some("bob")));
    assert!(!task.is_addon_enabled(Addon::NetworkGuard, Some("other.invalid"), Some("bob")));
    assert!(
        Policy::parse(
            r#"{"addons":{"credential_guard":{"enabled":"not-a-boolean"}}}"#,
            Format::Json
        )
        .is_err()
    );
}

#[test]
#[ignore = "historical Python oracle; set SAFEYOLO_POLICY_PYTHON"]
fn both_guard_enablement_controls_match_shipped_policy_engine() {
    use safeyolo_proxy::policy::Addon;
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let mut cases = vec![];
    for enabled in [true, false] {
        for required in [true, false] {
            for bypass in ["none", "domain", "client"] {
                for task in [
                    Value::Null,
                    json!({"addons":{"network_guard":{"enabled":false},"credential_guard":{"enabled":false}}}),
                    json!({"domains":{"*.example":{"bypass":["network_guard","credential_guard"]}}}),
                ] {
                    let mut document = json!({"permissions":[],"addons":{"network_guard":{"enabled":enabled},"credential_guard":{"enabled":!enabled}},"required":if required{json!(["network_guard","credential_guard"])}else{json!([])},"domains":{"api.example":{"addons":{"network_guard":{"enabled":!enabled},"credential_guard":{"enabled":enabled}}}},"clients":{"bob":{"addons":{"credential_guard":{"enabled":false}}}}});
                    if bypass == "domain" {
                        document["domains"]["*.example"] =
                            json!({"bypass":["network_guard","credential_guard"]});
                    }
                    if bypass == "client" {
                        document["clients"]["alice"] =
                            json!({"bypass":["network_guard","credential_guard"]});
                    }
                    cases.push(json!({"document":document,"task":task}));
                }
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let script = r#"
import json,sys,pathlib,tempfile,logging
from unittest.mock import patch
from safeyolo.policy.engine import PolicyEngine
from safeyolo.policy.models import UnifiedPolicy
logging.disable(logging.CRITICAL)
patch('safeyolo.policy.loader.write_event').start()
rows=[]
for case in json.load(sys.stdin):
 with tempfile.TemporaryDirectory() as directory:
  path=pathlib.Path(directory)/'policy.json';path.write_text(json.dumps(case['document']))
  engine=PolicyEngine(baseline_path=path);engine._loader.stop_watcher()
  if case['task'] is not None:engine._loader._task_policy=UnifiedPolicy.model_validate(case['task'])
  rows.append([engine.is_addon_enabled(addon,domain,client) for addon in ['network_guard','credential_guard'] for domain in [None,'','api.example','other.example','else.invalid'] for client in [None,'','alice','bob','ALICE']]);engine.done()
json.dump(rows,sys.stdout)
"#;
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
        .write_all(json!(cases).to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Value = serde_json::from_slice(&output.stdout).unwrap();
    let mut count = 0;
    for (index, case) in cases.iter().enumerate() {
        let mut p = Policy::parse(&case["document"].to_string(), Format::Json).unwrap();
        if !case["task"].is_null() {
            p = p
                .with_task_source(&case["task"].to_string(), Format::Json)
                .unwrap();
        }
        let mut row = vec![];
        for addon in [Addon::NetworkGuard, Addon::CredentialGuard] {
            for domain in [
                None,
                Some(""),
                Some("api.example"),
                Some("other.example"),
                Some("else.invalid"),
            ] {
                for client in [None, Some(""), Some("alice"), Some("bob"), Some("ALICE")] {
                    row.push(p.is_addon_enabled(addon, domain, client));
                    count += 1;
                }
            }
        }
        assert_eq!(json!(row), expected[index], "enablement case {index}");
    }
    eprintln!("{count} actual Python addon-enable queries");
}
