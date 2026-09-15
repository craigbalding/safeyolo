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
        "lists={blocked='hosts.txt'}\n[hosts]\n'*'={egress='allow'}",
        "[hosts]\n'x'={egress='allow',expires='2099-01-01'}",
        "[hosts]\n'x'={egress='allow'}\n[agents.alice.hosts]\n'x'={bypass=['network_guard']}",
    ] {
        assert_eq!(
            Policy::parse(source, Format::Toml).unwrap_err().kind,
            ErrorKind::Unsupported
        );
    }
    let unsupported = json!({"permissions":[{"action":"network:request","resource":"*","effect":"allow","condition":{"credential":"api:*"}}]}).to_string();
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
