use safeyolo_proxy::{
    credential_guard::*,
    credentials::Secret,
    network_guard::Identity,
    policy::{Format, NetworkRequest, Policy},
};
use serde_json::{Value, json};
fn policy(document: Value) -> Policy {
    Policy::parse(&document.to_string(), Format::Json).unwrap()
}
fn configured(sensor: Value) -> CredentialGuard {
    let guard = CredentialGuard::new(b"synthetic-key");
    guard.load_sensor_config(&sensor).unwrap();
    guard
}
fn observed(guard: &CredentialGuard, policy: &Policy, row: &Value) -> Value {
    let headers: Vec<_> = row["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|header| {
            (
                header[0].as_str().unwrap(),
                Secret::new(header[1].as_str().unwrap()),
            )
        })
        .collect();
    let headers: Vec<_> = headers
        .iter()
        .map(|(name, value)| Header { name, value })
        .collect();
    let pdp = match row["pdp"].as_str().unwrap_or("ready") {
        "missing" => Pdp::Unconfigured,
        "failed" => Pdp::Failed {
            policy,
            exception_type: "RuntimeError",
        },
        _ => Pdp::Ready(policy),
    };
    let request = Request {
        identity: match row["agent"].as_str().unwrap_or("alice") {
            "missing" => Identity::Unavailable,
            "conflict" => Identity::Conflict,
            agent => Identity::Resolved(agent),
        },
        host: row["host"].as_str().unwrap_or("api.example"),
        port: 443,
        method: row["method"].as_str().unwrap_or("GET"),
        path: row["path"]
            .as_str()
            .unwrap_or("/signed/%2F?Q=a%2Bb&Q=%252F"),
        scheme: row["scheme"].as_str().unwrap_or("https"),
        request_id: Some("req-generated"),
        connection_id: "conn-generated",
        prior_response: row["prior"].as_bool().unwrap_or(false),
        headers: &headers,
    };
    let outcome = guard
        .enforce(
            pdp,
            request,
            Options {
                block: row["block"].as_bool().unwrap_or(true),
            },
            1000.,
        )
        .unwrap();
    let bytes = outcome
        .response
        .as_ref()
        .map(|response| String::from_utf8(response.body_bytes()).unwrap());
    json!({"outcome":outcome,"body_bytes":bytes,"stats":guard.stats().unwrap()})
}
fn sensor() -> Value {
    json!({"policy_hash":"one","addons":{"credential_guard":{"use_default_credential_rules":false}},"credential_rules":[{"name":"Demo","patterns":["key-[a-z]+"],"allowed_hosts":["api.example"],"header_names":["authorization","x-api-key"]}]})
}
fn credential_policy(effect: &str) -> Value {
    json!({"permissions":[{"action":"credential:use","resource":"*","effect":effect},{"action":"network:request","resource":"*","effect":"allow"}]})
}
#[test]
fn defaults_rules_extract_basic_bearer_and_preserve_fingerprints_without_secrets() {
    let guard = configured(json!({}));
    let secret = Secret::new(format!("Bearer sk-proj-{}", "a".repeat(25)));
    let rows = guard
        .classify_headers(&[Header {
            name: "Authorization",
            value: &secret,
        }])
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].credential_type.as_deref(), Some("openai"));
    assert_eq!(rows[0].tier, 1);
    assert_eq!(rows[0].fingerprint.len(), 16);
    assert!(
        !serde_json::to_string(&rows)
            .unwrap()
            .contains(secret.expose_secret())
    );
    let guard = configured(sensor());
    let bearer = Secret::new("bEaReR \u{1f}key-synthetic\u{1f}");
    let basic = Secret::new("Basic dXNlcjprZXktc3ludGhldGlj");
    let a = guard
        .classify_headers(&[Header {
            name: "Authorization",
            value: &bearer,
        }])
        .unwrap();
    let b = guard
        .classify_headers(&[Header {
            name: "Authorization",
            value: &basic,
        }])
        .unwrap();
    assert_eq!(a, b);
    assert_eq!(a[0].rule, "Demo");
    assert_eq!(a[0].credential_type.as_deref(), Some("demo"));
}
#[test]
fn source_order_charges_credential_then_baseline_network_for_each_detection() {
    let guard = configured(sensor());
    let doc = json!({"permissions":[{"action":"credential:use","resource":"*","effect":"allow"},{"action":"network:request","resource":"*","effect":"budget","budget":1}]});
    let budget_policy = policy(doc);
    let row = json!({"headers":[["Authorization","Bearer key-first"],["x-api-key","key-second"],["api-key","key-third"]]});
    let result = observed(&guard, &budget_policy, &row);
    assert_eq!(
        result["outcome"]["evaluations"].as_array().unwrap().len(),
        2
    );
    assert_eq!(result["outcome"]["kind"], "allowed");
    let again = observed(&guard, &budget_policy, &row);
    assert_eq!(again["outcome"]["response"]["status"], 429);
    assert_eq!(again["stats"]["blocked"], 0);
    assert_eq!(again["stats"]["violations_total"], 1);
    assert_eq!(
        again["outcome"]["response"]["headers"],
        json!([
            ["Content-Type", "application/json"],
            ["X-Blocked-By", "credential-guard"]
        ])
    );
    let scoped = policy(
        json!({"permissions":[{"action":"credential:use","resource":"*","effect":"allow"},{"action":"network:request","resource":"*","effect":"deny"},{"action":"network:request","resource":"*","effect":"allow","condition":{"agent":"alice"}}]}),
    );
    assert_eq!(
        observed(&guard, &scoped, &row)["outcome"]["response"]["status"],
        403
    );
    let denied = policy(credential_policy("deny"));
    assert_eq!(
        observed(&guard, &denied, &row)["outcome"]["evaluations"][0]["required_checks"],
        json!([
            "rate_limit",
            "credential_detection",
            "credential_validation"
        ])
    );
    let p = policy(
        json!({"permissions":[{"action":"credential:use","resource":"*","effect":"deny"},{"action":"network:request","resource":"*","effect":"budget","budget":1}]}),
    );
    observed(&guard, &p, &row);
    for _ in 0..2 {
        assert_eq!(
            p.evaluate(
                NetworkRequest {
                    agent: None,
                    host: "api.example",
                    port: Some(443),
                    method: "GET",
                    path: "/"
                },
                1000.,
                true
            )
            .unwrap()
            .effect,
            safeyolo_proxy::policy::Effect::Allow
        );
    }
}
#[test]
fn warn_conflict_prior_response_disabled_and_error_have_distinct_side_effects() {
    let guard = configured(sensor());
    let p = policy(credential_policy("deny"));
    let row =
        json!({"headers":[["Authorization","key-first"],["x-api-key","key-second"]],"block":false});
    let result = observed(&guard, &p, &row);
    assert_eq!(result["outcome"]["kind"], "warned");
    assert_eq!(result["stats"]["violations_total"], 2);
    assert_eq!(result["stats"]["warned"], 2);
    assert_eq!(
        result["outcome"]["audit"][0]["approval"]["scope_hint"]["expected_hosts"],
        json!(["api.example"])
    );
    let mut conflict = row.clone();
    conflict["agent"] = json!("conflict");
    let result = observed(&guard, &p, &conflict);
    assert_eq!(result["outcome"]["response"]["status"], 403);
    assert_eq!(result["stats"]["blocked"], 1);
    assert!(
        result["outcome"]["evaluations"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    conflict["prior"] = json!(true);
    assert_eq!(
        observed(&guard, &p, &conflict)["outcome"]["kind"],
        "bypassed"
    );
    let mut missing = row.clone();
    missing["block"] = json!(true);
    missing["pdp"] = json!("missing");
    let result = observed(&guard, &p, &missing);
    assert_eq!(result["outcome"]["response"]["status"], 428);
    assert_eq!(result["outcome"]["evaluations"][0]["effect"], "error");
    assert!(result["outcome"]["audit"][0]["approval"].is_null());
    let disabled = policy(json!({"addons":{"credential_guard":{"enabled":false}}}));
    assert_eq!(
        observed(&guard, &disabled, &row)["outcome"]["kind"],
        "bypassed"
    );
}
#[test]
fn source_hash_reload_skips_bad_patterns_and_preserves_last_good_compatibility_candidate() {
    let guard = CredentialGuard::new(b"synthetic-key");
    assert!(guard.maybe_reload(Some(&json!({}))).unwrap().is_none());
    assert_eq!(guard.stats().unwrap().rules_count, 0);
    guard.maybe_reload(Some(&sensor())).unwrap().unwrap();
    let old = guard.stats().unwrap();
    assert!(guard.maybe_reload(None).unwrap().is_none());
    assert!(guard.maybe_reload(Some(&sensor())).unwrap().is_none());
    let mut candidate = sensor();
    candidate["policy_hash"] = json!("new");
    candidate["credential_rules"][0]["patterns"] = json!(["(?a:word)"]);
    assert_eq!(
        guard.maybe_reload(Some(&candidate)).unwrap_err(),
        Error::RegexCompatibility
    );
    assert_eq!(guard.stats().unwrap(), old);
    candidate["credential_rules"][0]["patterns"] = json!(["(", "(.+)+", "key-[a-z]+"]);
    let report = guard.maybe_reload(Some(&candidate)).unwrap().unwrap();
    assert_eq!(report.invalid_patterns, 2);
    assert_eq!(report.rules_count, 1);
    candidate["policy_hash"] = json!("empty");
    candidate["credential_rules"] = json!([]);
    guard.maybe_reload(Some(&candidate)).unwrap();
    assert_eq!(guard.stats().unwrap().rules_count, 0);
}
fn python(script: &str, input: &Value) -> Value {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
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
        .write_all(input.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
#[test]
#[ignore = "historical Python oracle; set SAFEYOLO_POLICY_PYTHON"]
fn header_detection_catalogue_entropy_and_extraction_match_python() {
    let mut values = vec![
        "ordinary".to_string(),
        "key-synthetic".into(),
        "Bearer key-synthetic".into(),
        "Bearer \u{1f}key-synthetic\u{1f}".into(),
        "Basic dXNlcjprZXktc3ludGhldGlj".into(),
        "Basic dXNlcjprZXktc3ludGhldGlj====".into(),
        "Basic dXNlcjprZXktc3ludGhldGlj==bad".into(),
        "Basic dXNlcjo=".into(),
        "Basic bm9jb2xvbg==".into(),
        "Basic /w==".into(),
        "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7".into(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        "零壱弐参四伍六七八九abcdefghij12345".into(),
    ];
    for prefix in [
        "sk-admin-",
        "sk-or-v1-",
        "sk-proj-",
        "sk-svcacct-",
        "sk-future-",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "github_pat_",
        "xai-",
        "gsk_",
        "AIza",
        "hf_",
        "hf_oauth_",
        "hf_jwt_",
        "npm_",
        "pypi-",
        "glpat-",
    ] {
        values.push(format!("{prefix}{}", "a".repeat(80)));
    }
    for family in ["api", "oat", "admin", "ort"] {
        values.push(format!("sk-ant-{family}03-{}AA", "A".repeat(93)));
    }
    let mut cases = Vec::new();
    for level in ["standard", "paranoid", "patterns-only", "unknown-mode"] {
        for header in [
            "Authorization",
            "authorization",
            "x-api-key",
            "api-key",
            "X-Random",
            "X-Safe-Marker",
        ] {
            for value in &values {
                let mut config = json!({"addons":{"credential_guard":{"detection_level":level,"safe_headers":{"safe_patterns":["safe-marker"]}}},"credential_rules":sensor()["credential_rules"]});
                if header == "authorization" {
                    config["addons"]["credential_guard"]["standard_auth_headers"] =
                        json!(["Authorization"]);
                }
                cases.push(json!({"sensor":config,"header":header,"value":value}));
            }
        }
    }
    // Basic padding permutations, control whitespace and empty first-pattern truthiness.
    for raw in [
        "dTph",
        "dTph=",
        "dTph===",
        "dTph====",
        "dTo=",
        "dTo==",
        "dTo===",
        "dTp4eA==",
        "dTp4eA===",
        "dTp4eA",
        "dTph\n",
        "dTph=YWJj",
    ] {
        cases.push(json!({"sensor":{"addons":{"credential_guard":{"detection_level":"paranoid","entropy":{"min_length":1,"min_charset_diversity":0,"min_shannon_entropy":0}}}},"header":"Authorization","value":format!("Basic {raw}")}));
    }
    for patterns in [json!(["", "key-[a-z]+"]), json!(["key-", "key-[a-z]+"])] {
        let mut config = sensor();
        config["credential_rules"][0]["patterns"] = patterns;
        cases.push(json!({"sensor":config,"header":"Authorization","value":"key-synthetic"}));
    }
    let mut config = sensor();
    config["credential_rules"] = json!([
        {"name":"first","patterns":["key-[a-z]+"],"allowed_hosts":[],"header_names":["x-ineligible"]},
        {"name":"second","patterns":["key-[a-z]+"],"allowed_hosts":[],"header_names":["authorization"]}
    ]);
    cases.push(json!({"sensor":config,"header":"Authorization","value":"key-synthetic"}));
    let expected = python(
        r#"
import json,sys,logging
from safeyolo.mitm_addons.credential_guard import CredentialGuard
from safeyolo.detection.credentials import analyze_headers,detect_credential_type
from safeyolo.detection.credential_catalog import build_default_rule_configs
from safeyolo.core.utils import hmac_fingerprint
logging.disable(logging.CRITICAL)
rows=[]
for case in json.load(sys.stdin):
 guard=CredentialGuard();guard._load_rules_from_policy(case['sensor']);guard._load_config_from_pdp(case['sensor'])
 detections=analyze_headers({case['header']:case['value']},guard.rules,guard.safe_headers_config,guard.config['entropy'],guard.config['standard_auth_headers'],guard.config['detection_level'])
 rows.append([{'rule':d['rule_name'],'credential_type':(detect_credential_type(d['credential'],guard.rules) or 'unknown').lower(),'header':d['header_name'],'fingerprint':hmac_fingerprint(d['credential'],b'synthetic-key'),'confidence':d['confidence'],'tier':d['tier']} for d in detections])
json.dump({'catalogue':build_default_rule_configs(),'rows':rows},sys.stdout)
"#,
        &json!(cases),
    );
    let catalogue: Value =
        serde_json::from_str(include_str!("../data/credential_guard/catalogue.json")).unwrap();
    assert_eq!(catalogue, expected["catalogue"]);
    for (index, case) in cases.iter().enumerate() {
        let guard = configured(case["sensor"].clone());
        let value = Secret::new(case["value"].as_str().unwrap());
        let actual = guard
            .classify_headers(&[Header {
                name: case["header"].as_str().unwrap(),
                value: &value,
            }])
            .unwrap();
        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            expected["rows"][index],
            "detector case {index}"
        );
    }
    eprintln!("{} actual Python header detection cases", cases.len());
}
#[test]
#[ignore = "historical Python oracle; set SAFEYOLO_POLICY_PYTHON"]
fn addon_wire_audit_trace_and_repeated_budget_charges_match_python() {
    let mut scenarios = vec![];
    for effect in ["allow", "deny", "prompt", "budget"] {
        let mut doc = credential_policy(effect);
        if effect == "budget" {
            doc["permissions"][0]["budget"] = json!(1);
        }
        let mut rows = vec![];
        for block in [true, false] {
            for agent in ["alice", "missing", "conflict"] {
                for pdp in ["ready", "missing", "failed"] {
                    rows.push(json!({"headers":[["Authorization","key-first"],["x-api-key","key-second"]],"block":block,"agent":agent,"pdp":pdp}));
                }
            }
        }
        rows.push(json!({"headers":[],"agent":"conflict","prior":true}));
        rows.push(json!({"headers":[]}));
        rows.push(
            json!({"headers":[["Authorization","key-first"]],"host":"_safeyolo.probe.internal"}),
        );
        rows.push(json!({"headers":[["Authorization","key-first"]],"method":"CONNECT","scheme":"","path":""}));
        scenarios.push(json!({"document":doc,"sensor":sensor(),"rows":rows}));
    }
    let mut docs = vec![
        json!({"permissions":[{"action":"credential:use","resource":"*","effect":"allow"},{"action":"network:request","resource":"*","effect":"budget","budget":1}]}),
        json!({"permissions":[]}),
        json!({"permissions":[{"action":"credential:use","resource":"*","effect":"allow"}]}),
        json!({"permissions":[{"action":"credential:use","resource":"*","effect":"allow"},{"action":"network:request","resource":"*","effect":"prompt"}]}),
    ];
    for enabled in [true, false] {
        for required in [true, false] {
            docs.push(json!({"permissions":credential_policy("deny")["permissions"],"required":if required{json!(["credential_guard"])}else{json!([])},"addons":{"credential_guard":{"enabled":enabled}},"domains":{"api.example":{"bypass":["credential_guard"]}}}));
        }
    }
    for doc in docs {
        scenarios.push(json!({"document":doc,"sensor":sensor(),"rows":[{"headers":[["Authorization","key-first"],["x-api-key","key-second"]]},{"headers":[["Authorization","key-third"]],"block":false},{"headers":[["Authorization","key-fourth"]]}]}));
    }
    let expected = python(
        r#"
import json,pathlib,sys,tempfile,logging
from unittest.mock import patch
from mitmproxy import ctx,http
from mitmproxy.test import tflow,taddons
from safeyolo.mitm_addons import credential_guard as module
from safeyolo.mitm_addons.credential_guard import CredentialGuard
from safeyolo.proxy_modes.unix_listener import UnixMode
from safeyolo.detection.credentials import analyze_headers,detect_credential_type
from safeyolo.core.utils import hmac_fingerprint
from pdp.client import LocalPolicyClient,PolicyClientConfig
logging.disable(logging.CRITICAL)
patch('safeyolo.policy.loader.write_event').start()
outputs=[]
for scenario in json.load(sys.stdin):
 with tempfile.TemporaryDirectory() as directory:
  path=pathlib.Path(directory)/'policy.json';path.write_text(json.dumps(scenario['document']))
  client=LocalPolicyClient(PolicyClientConfig(baseline_path=path));client._pdp._engine._loader.stop_watcher()
  guard=CredentialGuard();guard.hmac_secret=b'synthetic-key';guard._load_rules_from_policy(scenario['sensor']);guard._load_config_from_pdp(scenario['sensor']);rows=[]
  with taddons.context(guard),patch.object(guard,'_maybe_reload_rules'):
   for r in scenario['rows']:
    ctx.options.credguard_block=r.get('block',True)
    flow=tflow.tflow();flow.client_conn.id='conn-generated'
    flow.request=http.Request.make(r.get('method','GET'),'https://api.example/signed/%2F?Q=a%2Bb&Q=%252F',headers=[(k.encode(),v.encode()) for k,v in r['headers']])
    flow.request.host=r.get('host','api.example');flow.request.port=443;flow.request.method=r.get('method','GET');flow.request.path=r.get('path','/signed/%2F?Q=a%2Bb&Q=%252F');flow.request.scheme=r.get('scheme','https')
    flow.metadata['request_id']='req-generated'
    agent=r.get('agent','alice')
    if agent!='missing':flow.client_conn.proxy_mode=UnixMode.parse(f'unix:/tmp/10.0.0.5_{"alice" if agent=="conflict" else agent}/proxy.sock')
    if agent=='conflict':flow.metadata['agent']='bob'
    if r.get('prior'):flow.response=http.Response.make(451,b'prior')
    audits=[];steps=[];evaluations=[]
    def write_event(event,**kw):
     if event!='security.credential_guard':return
     row={key:kw[key] for key in ('kind','addon','decision','severity','summary','host','agent','request_id','details')};row['event']=event;row['approval']=kw['approval'].model_dump(mode='json') if kw.get('approval') else None;audits.append(row)
    def step(flow,**kw):
     details=kw.get('details') or {};steps.append({'hook':kw['hook'],'state':kw['state'],'outcome':kw.get('outcome'),'reason':kw.get('reason'),'detection_count':details.get('detection_count'),'status':details.get('status')})
    def get_client():
     if r.get('pdp')=='missing':raise RuntimeError('unconfigured')
     return client
    real=module.evaluate_credential_with_pdp
    def evaluate(*args,**kwargs):
     effect,context=real(*args,**kwargs);d=context.get('decision');credential=kwargs['credential'];rule=kwargs['rule_name']
     detections=analyze_headers(dict(flow.request.headers),guard.rules,guard.safe_headers_config,guard.config['entropy'],guard.config['standard_auth_headers'],guard.config['detection_level'])
     det=detections[len(evaluations)]
     finding={'rule':rule,'credential_type':None if r.get('pdp')=='missing' else (detect_credential_type(credential,guard.rules) or 'unknown').lower(),'header':det['header_name'],'fingerprint':hmac_fingerprint(credential,b'synthetic-key'),'confidence':det['confidence'],'tier':det['tier']}
     evaluations.append({'finding':finding,'effect':effect.value,'reason':context['reason'],'reason_codes':context['reason_codes'],'required_checks':d.checks.required if d else [],'budget_remaining':d.budget.remaining if d and d.budget else None});return effect,context
    real_evaluate=client.evaluate
    def client_evaluate(event):
     assert event.context is None or event.context.agent is None
     if r.get('pdp')=='failed':raise RuntimeError('synthetic failure')
     return real_evaluate(event)
    with patch.object(module,'get_policy_client',side_effect=get_client),patch.object(module,'evaluate_credential_with_pdp',side_effect=evaluate),patch('safeyolo.core.base.write_event',side_effect=write_event),patch('safeyolo.core.base.record_step',side_effect=step),patch.object(client,'evaluate',side_effect=client_evaluate),patch('safeyolo.policy.budget_tracker.time.time',return_value=1.):guard.request(flow)
    response=None;body_bytes=None
    if flow.response and not r.get('prior'):response={'status':flow.response.status_code,'body':json.loads(flow.response.content),'headers':[[k,v] for k,v in flow.response.headers.items() if k.lower()!='content-length']};body_bytes=flow.response.content.decode('ascii')
    metadata={key:flow.metadata[key] for key in ('blocked_by','block_reason','credential_fingerprint') if key in flow.metadata}
    kind='blocked' if response else ('bypassed' if steps and steps[0]['state']=='bypassed' else ('no_detection' if not evaluations else ('warned' if any(e['effect']!='allow' for e in evaluations) else 'allowed')))
    stats={**guard.get_stats(),**{key:getattr(guard.stats,key) for key in ('checks','allowed','blocked','warned')}}
    rows.append({'outcome':{'kind':kind,'response':response,'metadata':metadata,'trace':steps,'audit':audits,'evaluations':evaluations},'body_bytes':body_bytes,'stats':json.loads(json.dumps(stats))})
  client._pdp._engine.done();outputs.append(rows)
json.dump(outputs,sys.stdout)
"#,
        &json!(scenarios),
    );
    let mut count = 0;
    for (index, scenario) in scenarios.iter().enumerate() {
        let p = policy(scenario["document"].clone());
        let guard = configured(scenario["sensor"].clone());
        for (row_index, row) in scenario["rows"].as_array().unwrap().iter().enumerate() {
            let actual = observed(&guard, &p, row);
            assert_eq!(
                actual, expected[index][row_index],
                "scenario {index}, row {row_index}"
            );
            count += 1;
        }
    }
    eprintln!("{count} actual Python credential guard/PDP operations");
}

#[test]
fn empty_regex_truthiness_and_empty_entropy_failure_remain_distinct() {
    let mut source = sensor();
    source["credential_rules"][0]["patterns"] = json!(["", "key-[a-z]+"]);
    let guard = configured(source);
    let secret = Secret::new("key-synthetic");
    assert!(
        guard
            .classify_headers(&[Header {
                name: "Authorization",
                value: &secret
            }])
            .unwrap()
            .is_empty()
    );
    let guard = configured(json!({"addons":{"credential_guard":{"entropy":{"min_length":0}}}}));
    let empty = Secret::new("");
    assert_eq!(
        guard
            .classify_headers(&[Header {
                name: "Authorization",
                value: &empty
            }])
            .unwrap_err(),
        Error::EntropyRuntime
    );
}

#[test]
#[ignore = "historical Python oracle; set SAFEYOLO_POLICY_PYTHON"]
fn policy_hash_reload_and_cached_failures_match_live_python_guard() {
    let mut changed = sensor();
    changed["credential_rules"][0]["patterns"] = json!(["other-[a-z]+"]);
    let mut committed = changed.clone();
    committed["policy_hash"] = json!("two");
    let mut invalid_pattern = committed.clone();
    invalid_pattern["policy_hash"] = json!("three");
    invalid_pattern["credential_rules"][0]["patterns"] = json!(["(", "(.+)+", "key-[a-z]+"]);
    let mut empty = sensor();
    empty["policy_hash"] = json!("empty");
    empty["credential_rules"] = json!([]);
    let cases = json!([
        null,
        {},
        sensor(),
        changed,
        null,
        committed,
        invalid_pattern,
        empty
    ]);
    let expected = python(
        r#"
import json,sys,logging
from unittest.mock import patch
from safeyolo.mitm_addons.credential_guard import CredentialGuard
from safeyolo.detection.credentials import analyze_headers
from safeyolo.core.utils import hmac_fingerprint
logging.disable(logging.CRITICAL)
guard=CredentialGuard();rows=[]
for source in json.load(sys.stdin):
 def get():
  if source is None:raise RuntimeError('cache unavailable')
  return source
 with patch('safeyolo.core.config_cache.get_or_raise',side_effect=get):guard._maybe_reload_rules()
 detections=analyze_headers({'Authorization':'key-synthetic'},guard.rules,guard.safe_headers_config,guard.config.get('entropy',{}),guard.config.get('standard_auth_headers',['authorization']),guard.config.get('detection_level','standard'))
 rows.append({'rules':len(guard.rules),'findings':[{'rule':d['rule_name'],'fingerprint':hmac_fingerprint(d['credential'],b'synthetic-key')} for d in detections]})
json.dump(rows,sys.stdout)
"#,
        &cases,
    );
    let guard = CredentialGuard::new(b"synthetic-key");
    let value = Secret::new("key-synthetic");
    for (index, source) in cases.as_array().unwrap().iter().enumerate() {
        guard
            .maybe_reload((!source.is_null()).then_some(source))
            .unwrap();
        let rows: Vec<_> = guard
            .classify_headers(&[Header {
                name: "Authorization",
                value: &value,
            }])
            .unwrap()
            .into_iter()
            .map(|finding| json!({"rule":finding.rule,"fingerprint":finding.fingerprint}))
            .collect();
        assert_eq!(
            json!({"rules":guard.stats().unwrap().rules_count,"findings":rows}),
            expected[index],
            "reload step {index}"
        );
    }
    eprintln!(
        "{} actual Python cached reload steps",
        cases.as_array().unwrap().len()
    );
}

#[test]
fn clones_share_violation_counters_and_invalid_events_do_not_spend_budget() {
    let guard = configured(sensor());
    let p = policy(credential_policy("deny"));
    std::thread::scope(|scope| {
        let mut handles = vec![];
        for _ in 0..16 {
            let guard = guard.clone();
            let p = &p;
            handles.push(scope.spawn(move || {
                observed(
                    &guard,
                    p,
                    &json!({"headers":[["Authorization","key-synthetic"]],"block":false}),
                )
            }));
        }
        for handle in handles {
            assert_eq!(handle.join().unwrap()["outcome"]["kind"], "warned");
        }
    });
    assert_eq!(guard.stats().unwrap().violations_total, 16);
    assert_eq!(guard.stats().unwrap().warned, 16);
    let value = Secret::new("key-synthetic");
    let headers = [Header {
        name: "Authorization",
        value: &value,
    }];
    let result = guard.enforce(
        Pdp::Ready(&p),
        Request {
            identity: Identity::Resolved("alice"),
            host: "api.example",
            port: 0,
            method: "GET",
            path: "/",
            scheme: "https",
            request_id: Some("req-generated"),
            connection_id: "conn-generated",
            prior_response: false,
            headers: &headers,
        },
        Options::default(),
        1000.,
    );
    assert_eq!(result.unwrap_err(), Error::InvalidEvent);
    assert_eq!(guard.stats().unwrap().violations_total, 16);
}
