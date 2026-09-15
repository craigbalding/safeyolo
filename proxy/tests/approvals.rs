use std::{
    fs,
    sync::{Arc, Barrier},
};

use safeyolo_proxy::{
    approvals::{self, ErrorKind, NetworkPrompt, NetworkScope},
    policy::{Effect, Format, NetworkRequest, Policy},
};
use serde_json::{Value, json};

const SOURCE: &str = "# Operator policy comment\nbudget=1000\n[hosts]\n'*'={egress='prompt'}\n# Keep other destination\n'other.example'={egress='deny'}\n[agents.alice.hosts]\n'api.example:443'={egress='deny',expires=2099-01-01T00:00:00Z}\n";
fn request<'a>(host: &'a str, agent: Option<&'a str>, port: u16) -> NetworkRequest<'a> {
    NetworkRequest {
        host,
        agent,
        port: Some(port),
        method: "GET",
        path: "/",
    }
}
fn validate(source: &str) -> Result<(), String> {
    Policy::parse(source, Format::Toml)
        .map(|_| ())
        .map_err(|error| error.to_string())
}
fn setup() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.toml");
    fs::write(&path, SOURCE).unwrap();
    (directory, path)
}

#[test]
fn prompts_keep_agent_host_port_identity_and_reject_malformed_scope() {
    let scope = NetworkScope::new("[2001:0db8::1]:443", Some("alice"), Some(443)).unwrap();
    assert_eq!(
        scope.approval_key().unwrap(),
        r#"["alice","2001:db8::1",443]"#
    );
    assert_eq!(
        serde_json::to_value(NetworkPrompt::new(&scope).unwrap()).unwrap(),
        json!({"required":true,"approval_type":"network_egress","key":r#"["alice","2001:db8::1",443]"#,"target":"[2001:db8::1]:443","scope_hint":{"port":443}})
    );
    assert_ne!(
        scope.approval_key().unwrap(),
        NetworkScope::new("2001:db8::1", Some("bob"), Some(443))
            .unwrap()
            .approval_key()
            .unwrap()
    );
    assert_ne!(
        scope.approval_key().unwrap(),
        NetworkScope::new("2001:db8::1", Some("alice"), Some(22))
            .unwrap()
            .approval_key()
            .unwrap()
    );
    assert_eq!(
        NetworkScope::new("example.test", Some("a🦀é"), Some(443))
            .unwrap()
            .approval_key()
            .unwrap(),
        r#"["a\ud83e\udd80\u00e9","example.test",443]"#
    );
    for event in [
        json!({"host":"x","approval":{"scope_hint":{"port":true}}}),
        json!({"host":"x","approval":{"scope_hint":{"port":"443"}}}),
        json!({"host":"x","approval":{"scope_hint":3}}),
        json!({"host":"x","agent":42}),
        json!({"host":"x:22","details":{"port":443}}),
    ] {
        assert!(NetworkScope::from_event(&event).is_err(), "{event}");
    }
    let legacy = NetworkScope::from_event(&json!({"host":"x"})).unwrap();
    assert_eq!(legacy.port, None);
    assert!(NetworkPrompt::new(&legacy).is_err());
    assert_eq!(NetworkScope::from_event(&json!({"host":"x","agent":"alice","approval":{"scope_hint":{"port":443}},"details":{"port":22}})).unwrap().port,Some(443));
}

#[test]
fn durable_upserts_preserve_comments_and_agent_port_boundaries() {
    use std::os::unix::fs::PermissionsExt;
    let (_directory, path) = setup();
    let scope = NetworkScope::new("api.example", Some("alice"), Some(443)).unwrap();
    let result = approvals::allow_host(&path, &scope, Some(600), validate).unwrap();
    assert_eq!(
        serde_json::to_value(result).unwrap(),
        json!({"status":"added","host":"api.example","rate":600,"agent":"alice","port":443,"global_budget":1000,"rate_source":"host"})
    );
    approvals::allow_host(&path, &scope, Some(600), validate).unwrap();
    let source = fs::read_to_string(&path).unwrap();
    assert!(source.contains("# Operator policy comment"));
    assert!(source.contains("# Keep other destination"));
    assert!(
        !source.contains("2099-01-01"),
        "upsert replaces the whole old entry"
    );
    let policy = Policy::from_path(&path).unwrap();
    for (agent, port, effect) in [
        (Some("alice"), 443, Effect::Allow),
        (Some("alice"), 22, Effect::Prompt),
        (Some("bob"), 443, Effect::Prompt),
    ] {
        assert_eq!(
            policy
                .evaluate(request("api.example", agent, port), 0., false)
                .unwrap()
                .effect,
            effect
        );
    }
    approvals::deny_host(&path, &scope, Some("2099-01-01T02:00:00+02:00"), validate).unwrap();
    assert_eq!(
        Policy::from_path(&path)
            .unwrap()
            .evaluate(request("api.example", Some("alice"), 443), 0., false)
            .unwrap()
            .effect,
        Effect::Deny
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn activation_failure_rolls_back_exact_text_and_preserves_spent_budgets() {
    let (_directory, path) = setup();
    let source = "budget=10\n[hosts]\n'limited.example'={rate=1}\n";
    fs::write(&path, source).unwrap();
    let mut active = Policy::parse(source, Format::Toml).unwrap();
    let network = request("limited.example", Some("alice"), 443);
    for _ in 0..2 {
        assert_eq!(
            active.evaluate(network, 1000000., true).unwrap().effect,
            Effect::Allow
        );
    }
    let mut calls = 0;
    let error = approvals::allow_host(
        &path,
        &NetworkScope::new("new.example", None, Some(80)).unwrap(),
        Some(1),
        |candidate| {
            calls += 1;
            if calls == 1 {
                return Err("injected activation failure".into());
            }
            active = active
                .reload_from_source_at(candidate, Format::Toml, 1000000.)
                .map_err(|error| error.to_string())?;
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Activation);
    assert_eq!(calls, 2);
    assert_eq!(fs::read_to_string(&path).unwrap(), source);
    assert_eq!(
        active.evaluate(network, 1000000., true).unwrap().effect,
        Effect::BudgetExceeded
    );
    approvals::allow_host(
        &path,
        &NetworkScope::new("new.example", None, Some(80)).unwrap(),
        Some(1),
        |candidate| {
            active = active
                .reload_from_source_at(candidate, Format::Toml, 1000000.)
                .map_err(|error| error.to_string())?;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        active.evaluate(network, 1000000., true).unwrap().effect,
        Effect::BudgetExceeded
    );
}

#[test]
fn invalid_edits_leave_disk_and_activation_untouched() {
    let (_directory, path) = setup();
    let scope = NetworkScope::new("x.example", None, Some(443)).unwrap();
    for rate in [Some(0), Some(1001)] {
        assert_eq!(
            approvals::allow_host(&path, &scope, rate, |_| panic!(
                "invalid mutation activated"
            ))
            .unwrap_err()
            .kind,
            ErrorKind::Invalid
        );
    }
    assert_eq!(
        approvals::deny_host(&path, &scope, Some("broken timestamp"), |_| panic!(
            "invalid mutation activated"
        ))
        .unwrap_err()
        .kind,
        ErrorKind::Invalid
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), SOURCE);
    let yaml = path.with_extension("yaml");
    fs::write(&yaml, "hosts: {}\n").unwrap();
    assert_eq!(
        approvals::allow_host(&yaml, &scope, Some(1), |_| panic!(
            "unsupported format activated"
        ))
        .unwrap_err()
        .kind,
        ErrorKind::Unsupported
    );
}

#[test]
fn concurrent_edits_serialize_without_losing_other_approvals() {
    let (_directory, path) = setup();
    let barrier = Arc::new(Barrier::new(12));
    let workers: Vec<_> = (0..12)
        .map(|index| {
            let (path, barrier) = (path.clone(), barrier.clone());
            std::thread::spawn(move || {
                barrier.wait();
                approvals::allow_host(
                    &path,
                    &NetworkScope::new(&format!("{index}.example"), Some("bob"), Some(443))
                        .unwrap(),
                    Some(1),
                    validate,
                )
                .unwrap();
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    let policy = Policy::from_path(&path).unwrap();
    for index in 0..12 {
        assert_eq!(
            policy
                .evaluate(
                    request(&format!("{index}.example"), Some("bob"), 443),
                    0.,
                    false
                )
                .unwrap()
                .effect,
            Effect::Allow
        );
    }
}

#[test]
fn durable_expiry_prunes_agent_endpoints_without_expanding_other_scopes() {
    let (_directory, path) = setup();
    let scope = NetworkScope::new("api.example", Some("alice"), Some(443)).unwrap();
    approvals::deny_host(&path, &scope, Some("2026-01-01T00:00:00Z"), |_| Ok(())).unwrap();
    let count = approvals::prune_expired(&path, 1_767_225_600_000., validate).unwrap();
    assert_eq!(count, 1);
    let source = fs::read_to_string(&path).unwrap();
    assert!(!source.contains("api.example:443"));
    assert!(source.contains("# Keep other destination"));
    assert_eq!(
        Policy::from_path(&path)
            .unwrap()
            .evaluate(request("api.example", Some("alice"), 443), 0., false)
            .unwrap()
            .effect,
        Effect::Prompt
    );
    use std::os::unix::fs::MetadataExt;
    let inode = fs::metadata(&path).unwrap().ino();
    assert_eq!(
        approvals::prune_expired(&path, 1_767_225_600_000., |_| panic!(
            "no-op prune must not reactivate or rewrite policy"
        ))
        .unwrap(),
        0
    );
    assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
}

#[test]
#[ignore = "historical Python oracle; set SAFEYOLO_POLICY_PYTHON to the baseline environment"]
fn network_approval_mutations_and_expiry_match_python_with_named_agent_expiry_fix() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let operations = json!([
        {"kind":"allow","host":"api.example","agent":"alice","port":443,"rate":600},
        {"kind":"allow","host":"global.example","agent":null,"port":null,"rate":null},
        {"kind":"deny","host":"api.example","agent":"alice","port":22,"expires":"2099-01-01T02:00:00+02:00"},
        {"kind":"deny","host":"naive.example","agent":null,"port":80,"expires":"2099-01-01 01:02:03.123456"},
        {"kind":"deny","host":"forever.example","agent":null,"port":null,"expires":null},
        {"kind":"allow","host":"[2001:0db8::1]:443","agent":"a🦀é","port":443,"rate":5}
    ]);
    let timestamps = json!([
        "2026-01-01",
        "20260101",
        "2026-W01-4",
        "2026W014",
        "2026-W01",
        "2026W01",
        "2026-01-01T00:00:00Z",
        "2026-01-01 00:00:00.000001Z",
        "2026-01-01T00:00:00+01:30",
        "2026-01-01T00:00:00-01:30",
        "20260101T000000+0130",
        "2026-01-01🦀00:00",
        "2026-01-01T00",
        "2026-01-01T00.000001",
        "2026-01-01T00:00:00,1",
        "2026-01-01T00:00:00+00:00:30",
        "2026-01-01T00:00:00-00:00:30",
        "2026-01-01T00:00:00+00:00:00.5",
        "2026-01-01T00:00:00-00:00:00.5",
        "2026-01-01T00:00:00+00:99",
        "2026-01-01T00:00:00-00:99",
        "2026-01-01T00:00:00+00:00:99",
        "2026-01-01T00:00:00+23:59:99",
        "broken",
        "2026-02-30",
        "2026-01-01T",
        "2026-01-01T24:00:00",
        "2026-01-01T00:00:60",
        "2026-01-01T00:00:00z",
        "2026-01-01T00:00:00+24:00",
        true,
        3,
        null
    ]);
    let input = json!({"source":SOURCE,"operations":operations,"timestamps":timestamps});
    let script = r#"
import copy, json, pathlib, sys, tempfile
from datetime import UTC, datetime
from unittest.mock import patch
from safeyolo.core.destination import network_approval_key, destination_key, split_destination
from safeyolo.core.audit_schema import ApprovalRequest
from safeyolo.core.audit_stream import resolved_approval_key
from safeyolo.operator_approvals import network_scope
from safeyolo.policy.engine import PolicyEngine
from safeyolo.policy.loader import PolicyLoader
data=json.load(sys.stdin)
results=[]; prompts=[]
with tempfile.TemporaryDirectory() as directory:
    path=pathlib.Path(directory)/'policy.toml';path.write_text(data['source'])
    engine=PolicyEngine(baseline_path=path);engine._loader.stop_watcher()
    with patch('safeyolo.policy.engine.write_event'):
        for operation in data['operations']:
            fields={key:value for key,value in operation.items() if key != 'kind'}
            function=engine.add_host_allowance if operation['kind']=='allow' else engine.add_host_denial
            results.append(function(**fields))
            host,embedded=split_destination(operation['host']);port=operation['port'] or embedded
            if port:
                key=network_approval_key(operation['agent'],host,port)
                prompt=ApprovalRequest(required=True,approval_type='network_egress',key=key,target=destination_key(host,port),scope_hint={'port':port})
                prompts.append({'prompt':prompt.model_dump(mode='json'),'scope':network_scope({'host':host,'agent':operation['agent'],'approval':prompt.model_dump()}),'resolved':resolved_approval_key({'event':'admin.host_allowed','details':{'host':host,'port':port,'agent':operation['agent']}})})
    persisted=path.read_text();engine.done()
class Frozen(datetime):
    @classmethod
    def now(cls,tz=None): return cls(2026,1,1,tzinfo=UTC)
loader=PolicyLoader.__new__(PolicyLoader);loader._baseline_path=None
expired=[]
with patch('datetime.datetime',Frozen):
    for stamp in data['timestamps']:
        raw={'hosts':{'x':{'egress':'deny','expires':stamp}},'agents':{'alice':{'hosts':{'x':{'egress':'deny','expires':stamp}}}}}
        pruned=loader._prune_expired_hosts(raw)
        expired.append({'global':'x' not in pruned['hosts'],'agent':'x' not in pruned['agents']['alice']['hosts']})
with tempfile.TemporaryDirectory() as directory:
    path=pathlib.Path(directory)/'policy.toml';path.write_text("budget=10\n[hosts]\n'limited.example'={rate=1}\n")
    engine=PolicyEngine(baseline_path=path);engine._loader.stop_watcher()
    with patch('safeyolo.policy.budget_tracker.time.time',return_value=1000):
        budget_reload=[engine.evaluate_request('limited.example',method='GET',port=443).effect for _ in range(2)]
        engine._loader.reload()
        budget_reload.append(engine.evaluate_request('limited.example',method='GET',port=443).effect)
    engine.done()
json.dump({'results':results,'prompts':prompts,'persisted':persisted,'expired':expired,'budget_reload':budget_reload},sys.stdout)
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
    let (_directory, path) = setup();
    let mut prompts = Vec::new();
    let mut results = Vec::new();
    for operation in operations.as_array().unwrap() {
        let scope = NetworkScope::new(
            operation["host"].as_str().unwrap(),
            operation["agent"].as_str(),
            operation["port"].as_u64().map(|port| port as u16),
        )
        .unwrap();
        results.push(if operation["kind"] == "allow" {
            serde_json::to_value(
                approvals::allow_host(&path, &scope, operation["rate"].as_u64(), validate).unwrap(),
            )
            .unwrap()
        } else {
            serde_json::to_value(
                approvals::deny_host(&path, &scope, operation["expires"].as_str(), validate)
                    .unwrap(),
            )
            .unwrap()
        });
        if scope.port.is_some() {
            let mut hint = json!({"port":scope.port});
            if let Some(agent) = &scope.agent {
                hint["agent"] = json!(agent);
            }
            prompts.push(json!({"prompt":NetworkPrompt::new(&scope).unwrap(),"scope":hint,"resolved":scope.resolved_key().unwrap()}));
        }
    }
    assert_eq!(json!(results), python["results"]);
    assert_eq!(json!(prompts), python["prompts"]);
    let policy = Policy::parse(
        "budget=10\n[hosts]\n'limited.example'={rate=1}\n",
        Format::Toml,
    )
    .unwrap();
    let mut budget_reload = Vec::new();
    for _ in 0..2 {
        budget_reload.push(
            policy
                .evaluate(request("limited.example", None, 443), 1_000_000., true)
                .unwrap()
                .effect,
        );
    }
    let reloaded = policy
        .reload_from_source_at(
            "budget=10\n[hosts]\n'limited.example'={rate=1}\n",
            Format::Toml,
            1_000_000.,
        )
        .unwrap();
    budget_reload.push(
        reloaded
            .evaluate(request("limited.example", None, 443), 1_000_000., true)
            .unwrap()
            .effect,
    );
    assert_eq!(json!(budget_reload), python["budget_reload"]);
    let native: toml::Value = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let baseline: toml::Value = toml::from_str(python["persisted"].as_str().unwrap()).unwrap();
    assert_eq!(
        native, baseline,
        "persisted typed TOML values, including offset/naive expiry, must match"
    );
    let mut intentional_fixes = 0;
    for (index, stamp) in timestamps.as_array().unwrap().iter().enumerate() {
        let source=json!({"hosts":{"*":{"egress":"allow"},"x":{"egress":"deny","expires":stamp}},"agents":{"alice":{"hosts":{"x":{"egress":"deny","expires":stamp}}}}}).to_string();
        let policy = Policy::parse_at(&source, Format::Json, 1_767_225_600_000.).unwrap();
        let global = policy
            .evaluate(request("x", None, 80), 0., false)
            .unwrap()
            .effect
            == Effect::Allow;
        let agent = policy
            .evaluate(request("x", Some("alice"), 80), 0., false)
            .unwrap()
            .effect
            == Effect::Allow;
        assert_eq!(
            json!(global),
            python["expired"][index]["global"],
            "expiry {stamp}"
        );
        assert!(
            !python["expired"][index]["agent"].as_bool().unwrap(),
            "baseline defect must stay named"
        );
        assert_eq!(
            agent, global,
            "native fix prunes expired agent entries with the same timestamp rules"
        );
        if agent {
            intentional_fixes += 1;
        }
    }
    eprintln!(
        "Python oracle: {} durable mutations, {} prompt scopes, {} expiry cases; {} intentional agent-expiry corrections",
        results.len(),
        prompts.len(),
        timestamps.as_array().unwrap().len(),
        intentional_fixes
    );
}
