use safeyolo_proxy::{
    network_guard::*,
    policy::{Format, Policy},
};
use serde_json::{Value, json};

fn policy(document: Value) -> Policy {
    Policy::parse(&document.to_string(), Format::Json).unwrap()
}
fn request(host: &str) -> Request<'_> {
    Request {
        identity: Identity::Resolved("alice"),
        host,
        decode_ace_for_inspection: false,
        port: 443,
        method: "GET",
        path: "/signed/%2F?X=a%2Bb&X=%252F",
        scheme: "https",
        request_id: Some("req-generated"),
        connection_id: "conn-generated",
        prior_response: false,
    }
}

#[test]
fn transport_ace_inspection_preserves_policy_host_and_precedes_budget() {
    for host in [
        "xn--pi-6kc.invalid",
        "XN--pi-6kc.invalid",
        "XN--pi-fia905a.invalid",
        "XN--pi-6kc646z.invalid",
    ] {
        let policy = policy(
            json!({"permissions":[{"action":"network:request","resource":"*","effect":"budget","budget":1}]}),
        );
        let guard = NetworkGuard::new();
        let mut req = request(host);
        req.decode_ace_for_inspection = true;
        let outcome = guard
            .enforce(Pdp::Ready(&policy), req, Options::default(), 1000.)
            .unwrap();
        assert_eq!(outcome.kind, OutcomeKind::Blocked, "{host}");
        assert_eq!(
            outcome.response.as_ref().unwrap().body["type"],
            "homoglyph_attack"
        );
        assert_eq!(outcome.audit.as_ref().unwrap().host, host);
        assert!(outcome.pdp.is_none());
        assert_eq!(
            guard
                .enforce(
                    Pdp::Ready(&policy),
                    request(host),
                    Options {
                        homoglyph: false,
                        ..Options::default()
                    },
                    1000.
                )
                .unwrap()
                .kind,
            OutcomeKind::Allowed
        );
    }
}

#[test]
fn ace_inspection_errors_follow_configured_guard_modes_and_bypasses() {
    let host = "XN--ib9b.invalid"; // Raw Punycode represents a lone surrogate.
    for (options, bypass, expected) in [
        (Options::default(), false, OutcomeKind::Blocked),
        (
            Options {
                block: false,
                ..Options::default()
            },
            false,
            OutcomeKind::Warned,
        ),
        (
            Options {
                homoglyph: false,
                ..Options::default()
            },
            false,
            OutcomeKind::Allowed,
        ),
        (
            Options {
                enabled: false,
                ..Options::default()
            },
            false,
            OutcomeKind::Bypassed,
        ),
        (Options::default(), true, OutcomeKind::Bypassed),
    ] {
        let mut document =
            json!({"permissions":[{"action":"network:request","resource":"*","effect":"allow"}]});
        if bypass {
            document["domains"] = json!({host:{"bypass":["network_guard"]}});
        }
        let policy = policy(document);
        let guard = NetworkGuard::new();
        let mut req = request(host);
        req.decode_ace_for_inspection = true;
        let outcome = guard
            .enforce(Pdp::Ready(&policy), req, options, 1000.)
            .unwrap();
        assert_eq!(outcome.kind, expected);
        if matches!(expected, OutcomeKind::Blocked | OutcomeKind::Warned) {
            assert_eq!(
                outcome.audit.unwrap().details["reason"],
                "Hostname inspection failed"
            );
            assert!(outcome.pdp.is_none());
        }
        if expected == OutcomeKind::Bypassed {
            assert_eq!(guard.stats().unwrap().checks, 0);
        }
    }
}

#[test]
fn gates_precede_identity_homoglyph_and_budget_without_spending() {
    let policy = policy(
        json!({"permissions":[{"action":"network:request","resource":"*","effect":"budget","budget":1}],"domains":{"*.example":{"bypass":["network_guard"]}}}),
    );
    let guard = NetworkGuard::new();
    let mut req = request("аpi.example");
    req.identity = Identity::Conflict;
    let disabled = guard
        .enforce(
            Pdp::Ready(&policy),
            req,
            Options {
                enabled: false,
                ..Options::default()
            },
            1000.,
        )
        .unwrap();
    assert_eq!(disabled.trace.reason, Some(BypassReason::AddonDisabled));
    req.prior_response = true;
    assert_eq!(
        guard
            .enforce(Pdp::Ready(&policy), req, Options::default(), 1000.)
            .unwrap()
            .trace
            .reason,
        Some(BypassReason::PriorResponse)
    );
    req.prior_response = false;
    let denied = guard
        .enforce(Pdp::Ready(&policy), req, Options::default(), 1000.)
        .unwrap();
    assert_eq!(
        denied.response.unwrap().body["reason"],
        "Trusted agent identity sources disagree (fail-closed)"
    );
    assert!(denied.pdp.is_none());
    req.identity = Identity::Resolved("alice");
    let bypass = guard
        .enforce(Pdp::Ready(&policy), req, Options::default(), 1000.)
        .unwrap();
    assert_eq!(bypass.trace.reason, Some(BypassReason::PolicyDisabled));
    assert_eq!(guard.stats().unwrap().checks, 1);
    // Required resists a configured bypass. Global runtime disable remains first.
    let required = policy_with_required();
    let blocked = guard
        .enforce(Pdp::Ready(&required), req, Options::default(), 1000.)
        .unwrap();
    assert_eq!(blocked.response.unwrap().body["type"], "homoglyph_attack");
    assert!(blocked.pdp.is_none());
    let clean = request("clean.example");
    for _ in 0..2 {
        assert_eq!(
            guard
                .enforce(Pdp::Ready(&required), clean, Options::default(), 1000.)
                .unwrap()
                .kind,
            OutcomeKind::Allowed
        );
    }
    assert_eq!(
        guard
            .enforce(Pdp::Ready(&required), clean, Options::default(), 1000.)
            .unwrap()
            .response
            .unwrap()
            .status,
        429
    );
}
fn policy_with_required() -> Policy {
    policy(
        json!({"permissions":[{"action":"network:request","resource":"*","effect":"budget","budget":1}],"required":["network_guard"],"budgets":{"network:request":1},"domains":{"*.example":{"bypass":["network_guard"]}}}),
    )
}

#[test]
fn one_budget_charge_is_shared_atomically_and_connect_is_separate() {
    let policy = policy(
        json!({"permissions":[{"action":"network:request","resource":"*","effect":"budget","budget":1}]}),
    );
    let guard = NetworkGuard::new();
    let barrier = std::sync::Barrier::new(16);
    let results = std::thread::scope(|scope| {
        let tasks: Vec<_> = (0..16)
            .map(|_| {
                let guard = guard.clone();
                let policy = &policy;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    guard
                        .enforce(
                            Pdp::Ready(policy),
                            request("api"),
                            Options::default(),
                            1000.,
                        )
                        .unwrap()
                })
            })
            .collect();
        tasks
            .into_iter()
            .map(|task| task.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        results
            .iter()
            .filter(|out| out.kind == OutcomeKind::Allowed)
            .count(),
        2
    );
    assert_eq!(
        guard.stats().unwrap(),
        Stats {
            checks: 16,
            allowed: 2,
            blocked: 14,
            warned: 0,
            rate_limited: 14
        }
    );
    let mut req = request("api");
    req.method = "CONNECT";
    req.path = "";
    req.scheme = "";
    let out = guard
        .enforce(Pdp::Ready(&policy), req, Options::default(), 1000.)
        .unwrap();
    assert_eq!(out.kind, OutcomeKind::Allowed);
    let event = out.policy_event.unwrap();
    assert_eq!(event.path, "");
    assert_eq!(event.scheme, "");
    assert!(event.query_string.is_none());
    assert_eq!(out.audit.unwrap().summary, "CONNECT to api:443 allowed");
    assert_eq!(out.trace.hook, "http_connect");
}

#[test]
fn prompt_intent_preserves_agent_host_port_and_warn_does_not_persist() {
    let policy = policy(
        json!({"permissions":[{"action":"network:request","resource":"*","effect":"prompt"}]}),
    );
    let guard = NetworkGuard::new();
    for (agent, host, port) in [
        ("alice", "Example.test", 443),
        ("bob", "Example.test", 8443),
        ("a\u{7f}b", "api", 443),
        ("é😀", "2001:db8::1", 443),
    ] {
        let mut req = request(host);
        req.identity = Identity::Resolved(agent);
        req.port = port;
        for block in [false, true] {
            let out = guard
                .enforce(
                    Pdp::Ready(&policy),
                    req,
                    Options {
                        block,
                        ..Options::default()
                    },
                    1000.,
                )
                .unwrap();
            let approval = out.audit.unwrap().approval.unwrap();
            let key: Value = serde_json::from_str(&approval.key).unwrap();
            assert_eq!(key, json!([agent, host, port]));
            assert_eq!(
                approval.target,
                if host.contains(':') {
                    format!("[{host}]:{port}")
                } else {
                    format!("{host}:{port}")
                }
            );
            assert_eq!(out.response.is_some(), block);
            assert!(out.metadata.get("block_reason").is_none());
        }
    }
    assert_eq!(
        guard.stats().unwrap(),
        Stats {
            checks: 8,
            allowed: 0,
            blocked: 4,
            warned: 4,
            rate_limited: 0
        }
    );
}

#[test]
fn response_bytes_headers_metadata_errors_and_probe_are_explicit() {
    let policy = policy(
        json!({"permissions":[{"action":"network:request","resource":"*","effect":"deny"}]}),
    );
    let guard = NetworkGuard::new();
    let req = request("api");
    let out = guard
        .enforce(Pdp::Ready(&policy), req, Options::default(), 1000.)
        .unwrap();
    let response = out.response.unwrap();
    assert_eq!(response.status, 403);
    assert_eq!(
        response.headers,
        vec![
            ("Content-Type".into(), "application/json".into()),
            ("X-Blocked-By".into(), "network-guard".into()),
            ("X-SafeYolo-Request-Id".into(), "req-generated".into())
        ]
    );
    assert_eq!(response.body_bytes(),br#"{"error": "Access denied by proxy", "domain": "api", "reason": "Decision: deny", "type": "access_denied", "action": "self_correct", "reflection": "Network access to api is not in the security policy. If you need this domain, ask the operator to add it to policy.yaml."}"#);
    let event = out.policy_event.unwrap();
    assert_eq!(event.path, "/signed/%2F");
    assert_eq!(event.query_string.as_deref(), Some("X=a%2Bb&X=%252F"));
    assert_eq!(req.path, "/signed/%2F?X=a%2Bb&X=%252F");
    for block in [false, true] {
        let missing = guard
            .enforce(
                Pdp::Unconfigured,
                req,
                Options {
                    block,
                    ..Options::default()
                },
                1000.,
            )
            .unwrap();
        assert_eq!(
            missing.audit.unwrap().details["reason"],
            "PDP not configured (fail-closed)"
        );
        let failure = guard
            .enforce(
                Pdp::Failed {
                    policy: &policy,
                    reason: "Internal evaluation error: RuntimeError",
                },
                req,
                Options {
                    block,
                    ..Options::default()
                },
                1000.,
            )
            .unwrap();
        assert_eq!(
            failure.audit.unwrap().details["reason"],
            "PDP error: Internal evaluation error: RuntimeError"
        );
        assert_eq!(failure.response.is_some(), block);
    }
    let probe = guard
        .enforce(
            Pdp::Ready(&policy),
            request("_SafeYolo.Probe.Internal"),
            Options::default(),
            1000.,
        )
        .unwrap();
    assert_eq!(probe.kind, OutcomeKind::Allowed);
    assert_eq!(
        probe.pdp.unwrap().reason_codes,
        vec!["INTERNAL_PIPELINE_PROBE"]
    );
    let root_dot = guard
        .enforce(
            Pdp::Ready(&policy),
            request("_safeyolo.probe.internal."),
            Options::default(),
            1000.,
        )
        .unwrap();
    assert_eq!(
        root_dot.kind,
        OutcomeKind::Blocked,
        "intrinsic PDP probe predicate is separate from transport's stronger local containment"
    );
    let mut invalid = request("api");
    invalid.port = 0;
    assert!(
        guard
            .enforce(Pdp::Ready(&policy), invalid, Options::default(), 1000.)
            .is_err()
    );
    assert_eq!(
        guard
            .enforce(Pdp::Ready(&policy), req, Options::default(), f64::NAN)
            .unwrap()
            .response
            .unwrap()
            .status,
        403
    );
}

#[test]
fn source_unicode_behavior_is_not_a_general_idn_ban() {
    for domain in [
        "api.openai.com",
        "ρτ.τ",
        "例例",
        "xn--pi-6kc.openai.com",
        "eé.example",
    ] {
        assert!(!dangerous_domain(domain), "{domain}");
    }
    for domain in [
        "аpi.openai.com",
        "api.οpenai.com",
        "例え.com",
        "a\u{301}",
        "a\u{378}",
    ] {
        assert!(dangerous_domain(domain), "{domain}");
    }
    assert_eq!(
        sanitize("a\r\n\x1b[31m\u{301}??b\u{2028}\u{2029}😀"),
        "a?b?😀"
    );
    assert_eq!(
        sanitize(&"é".repeat(201)),
        format!("{}...", "é".repeat(200))
    );
    assert_eq!(
        sanitize(&format!("{}\u{301}\u{301}", "é".repeat(199))),
        format!("{}?", "é".repeat(199))
    );
}

fn oracle_scenarios() -> Vec<Value> {
    let documents = vec![
        json!({"permissions":[]}),
        json!({"permissions":[{"action":"network:request","resource":"*","effect":"allow"}]}),
        json!({"permissions":[{"action":"network:request","resource":"*","effect":"deny"}]}),
        json!({"permissions":[{"action":"network:request","resource":"*","effect":"prompt"}]}),
        json!({"permissions":[{"action":"network:request","resource":"*","effect":"budget","budget":1}],"budgets":{"network:request":1}}),
        json!({"permissions":[{"action":"network:request","resource":"*","effect":"allow"},{"action":"network:request","resource":"*","effect":"deny","condition":{"agent":"bob"}}],"domains":{"*.internal":{"bypass":["network_guard"]}}}),
        json!({"permissions":[{"action":"network:request","resource":"*","effect":"deny"}],"domains":{"*.internal":{"bypass":["network_guard"]}},"required":["network_guard"]}),
        json!({"permissions":[{"action":"network:request","resource":"*","effect":"deny"}],"clients":{"alice":{"bypass":["network_guard"]}}}),
        json!({"permissions":[{"action":"network:request","resource":"*","effect":"deny"}],"addons":{"network_guard":{"enabled":false}}}),
        json!({"permissions":[{"action":"network:request","resource":"api/*","effect":"deny","condition":{"path_prefix":"/private/"}},{"action":"network:request","resource":"*","effect":"allow"}]}),
        json!({"default":{"egress":"prompt","budget":1},"hosts":{"api":{"egress":"allow","budget":1},"other:8443":{"egress":"deny"}},"agents":{"bob":{"hosts":{"api":{"egress":"deny"}}}}}),
    ];
    documents.into_iter().map(|document|{
        let mut requests=Vec::new();
        for block in [true,false] {
            for (host,agent,port,method,path,scheme) in [
                ("api","alice",443,"GET","/private/%2F?signature=raw%2B+&x=1&x=2","https"),
                ("api","alice",443,"GET","/public?a=%252F","https"),
                ("api","alice",443,"GET","/public?","https"),
                ("api","bob",443,"POST","/public","https"),
                ("api","a\u{7f}b",443,"GET","/public","https"),
                ("api","alice",443,"CONNECT","",""),
                ("api","alice",443,"CONNECT","",""),
                ("api","alice",443,"CONNECT","",""),
                ("other","bob",8443,"GET","/","https"),
                ("2001:db8::1","alice",443,"GET","/","https"),
                ("api","unavailable",80,"GET","/","http"),
                ("safe.internal","alice",443,"GET","/","https"),
                ("safe.internal","conflict",443,"GET","/","https"),
                ("аpi.example","alice",443,"GET","/","https"),
                ("例え.com","alice",443,"GET","/","https"),
                ("_safeyolo.probe.internal","alice",80,"GET","/__pipeline_probe","http"),
                ("_safeyolo.probe.internal.","alice",80,"GET","/__pipeline_probe","http"),
            ] {
                requests.push(json!({"host":host,"agent":agent,"port":port,"method":method,"path":path,"scheme":scheme,"block":block,"enabled":true,"homoglyph":true,"prior_response":false,"pdp":"ready"}));
            }
            for (enabled,prior_response,homoglyph,pdp) in [(false,false,true,"ready"),(true,true,true,"ready"),(true,false,false,"ready"),(true,false,true,"missing"),(true,false,true,"error")] {
                requests.push(json!({"host":"api","agent":"alice","port":443,"method":"GET","path":"/","scheme":"https","block":block,"enabled":enabled,"homoglyph":homoglyph,"prior_response":prior_response,"pdp":pdp}));
            }
        }
        json!({"document":document,"requests":requests})
    }).collect()
}

#[test]
#[ignore = "requires existing Python production environment; set SAFEYOLO_POLICY_PYTHON"]
fn guard_wire_intents_and_budget_state_match_actual_python_pipeline() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let scenarios = oracle_scenarios();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let script = r#"
import json,pathlib,sys,tempfile,logging
from unittest.mock import patch
from mitmproxy import ctx,http
from mitmproxy.test import tflow,taddons
from safeyolo.mitm_addons.network_guard import NetworkGuard
from safeyolo.proxy_modes.unix_listener import UnixMode
from pdp.client import LocalPolicyClient,PolicyClientConfig
logging.disable(logging.CRITICAL)
# Policy-load audits are outside this oracle; intercept before constructing PDP.
patch('safeyolo.policy.loader.write_event').start()
outputs=[]
for scenario in json.load(sys.stdin):
 with tempfile.TemporaryDirectory() as directory:
  path=pathlib.Path(directory)/'policy.json';path.write_text(json.dumps(scenario['document']))
  client=LocalPolicyClient(PolicyClientConfig(baseline_path=path));client._pdp._engine._loader.stop_watcher()
  guard=NetworkGuard();rows=[]
  with taddons.context(guard):
   for r in scenario['requests']:
    ctx.options.update(network_guard_enabled=r['enabled'],network_guard_block=r['block'],network_guard_homoglyph=r['homoglyph'])
    flow=tflow.tflow();flow.client_conn.id='conn-generated'
    flow.request.host=r['host'];flow.request.port=r['port'];flow.request.method=r['method'];flow.request.path=r['path'];flow.request.scheme=r['scheme']
    # Header identity and request IDs never supply trusted sensor metadata.
    flow.request.headers['X-SafeYolo-Agent']='mallory';flow.request.headers['X-SafeYolo-Request-Id']='forged-id'
    flow.metadata['request_id']='req-generated'
    # Legacy trusted IP-map identities admit strings beyond the UDS name grammar.
    discovery=None
    if '\x7f' in r['agent']:
     class TrustedMap:
      def get_client_for_ip(self,ip):return r['agent']
     discovery=TrustedMap()
    elif r['agent']!='unavailable':
     agent='alice' if r['agent']=='conflict' else r['agent']
     flow.client_conn.proxy_mode=UnixMode.parse(f'unix:/tmp/10.0.0.5_{agent}/proxy.sock')
    if r['agent'] in ('unavailable','conflict'):flow.metadata['agent']='mallory'
    if r['prior_response']:flow.response=http.Response.make(451,b'prior response')
    audits=[];steps=[];events=[];decisions=[]
    real_evaluate=client.evaluate
    def evaluate(event):
     decision=real_evaluate(event)
     events.append({'agent':event.context.agent if event.context else None,**{key:getattr(event.http,key) for key in ('host','port','method','path','scheme','query_string')}})
     decisions.append({'effect':decision.effect.value,'reason':decision.reason,'reason_codes':decision.reason_codes,'required_checks':decision.checks.required,'budget_remaining':decision.budget.remaining if decision.budget else None})
     return decision
    def write_event(event,**kwargs):
     if event!='security.network_guard':return
     keys=('kind','addon','decision','severity','summary','host','agent','request_id','details')
     row={key:kwargs[key] for key in keys};row['event']=event;row['approval']=kwargs['approval'].model_dump(mode='json') if kwargs.get('approval') else None;audits.append(row)
    def step(flow,**kwargs):steps.append(kwargs)
    def get_client():
     if r['pdp']=='missing':raise RuntimeError('not configured')
     return client
    original_request=client._pdp._engine.evaluate_request
    def engine_request(*args,**kwargs):
     if r['pdp']=='error':raise RuntimeError('synthetic exception must not be copied')
     return original_request(*args,**kwargs)
    with patch('safeyolo.mitm_addons.network_guard.get_policy_client',side_effect=get_client),patch('safeyolo.core.base.get_policy_client',side_effect=get_client),patch.object(guard,'_resolve_service_discovery',return_value=discovery),patch('safeyolo.core.base.write_event',side_effect=write_event),patch('safeyolo.core.base.record_step',side_effect=step),patch.object(client,'evaluate',side_effect=evaluate),patch.object(client._pdp._engine,'evaluate_request',side_effect=engine_request),patch('safeyolo.policy.budget_tracker.time.time',return_value=1.):
     if r['method']=='CONNECT':guard.http_connect(flow)
     else:guard.request(flow)
    assert len(steps)==1,steps
    observed=steps[0];trace={'hook':observed['hook'],'state':observed['state'],'outcome':observed.get('outcome'),'reason':observed.get('reason'),'status':(observed.get('details') or {}).get('status')}
    assert len(events)<=1 and len(decisions)<=1 and len(audits)<=1
    response=None;body_bytes=None
    if flow.response and not r['prior_response']:
     response={'status':flow.response.status_code,'body':json.loads(flow.response.content),'headers':[[k,v] for k,v in flow.response.headers.items() if k.lower()!='content-length']};body_bytes=flow.response.content.decode('ascii')
    metadata={key:flow.metadata[key] for key in ('blocked_by','block_reason','ratelimit_remaining') if key in flow.metadata}
    rows.append({'kind':trace['outcome'] or 'bypassed','response':response,'body_bytes':body_bytes,'metadata':metadata,'trace':trace,'audit':audits[0] if audits else None,'policy_event':events[0] if events else None,'pdp':decisions[0] if decisions else None,'stats':guard.get_stats()})
  client._pdp._engine.done();outputs.append(rows)
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
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_vec(&scenarios).unwrap().as_slice())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let expected: Value = serde_json::from_slice(&result.stdout).unwrap();
    let mut count = 0;
    for (index, scenario) in scenarios.iter().enumerate() {
        let policy = policy(scenario["document"].clone());
        let guard = NetworkGuard::new();
        for (offset, r) in scenario["requests"].as_array().unwrap().iter().enumerate() {
            let identity = match r["agent"].as_str().unwrap() {
                "unavailable" => Identity::Unavailable,
                "conflict" => Identity::Conflict,
                agent => Identity::Resolved(agent),
            };
            let req = Request {
                identity,
                host: r["host"].as_str().unwrap(),
                decode_ace_for_inspection: false,
                port: r["port"].as_u64().unwrap() as u16,
                method: r["method"].as_str().unwrap(),
                path: r["path"].as_str().unwrap(),
                scheme: r["scheme"].as_str().unwrap(),
                request_id: Some("req-generated"),
                connection_id: "conn-generated",
                prior_response: r["prior_response"].as_bool().unwrap(),
            };
            let options = Options {
                enabled: r["enabled"].as_bool().unwrap(),
                block: r["block"].as_bool().unwrap(),
                homoglyph: r["homoglyph"].as_bool().unwrap(),
            };
            let pdp = match r["pdp"].as_str().unwrap() {
                "missing" => Pdp::Unconfigured,
                "error" => Pdp::Failed {
                    policy: &policy,
                    reason: "Internal evaluation error: RuntimeError",
                },
                _ => Pdp::Ready(&policy),
            };
            let out = guard.enforce(pdp, req, options, 1000.).unwrap();
            let mut observed = serde_json::to_value(&out).unwrap();
            observed["stats"] = guard.stats_json(options.enabled).unwrap();
            observed["body_bytes"] = out
                .response
                .map(|response| Value::String(String::from_utf8(response.body_bytes()).unwrap()))
                .unwrap_or(Value::Null);
            assert_eq!(
                observed, expected[index][offset],
                "document {index}, request {offset}: {r}"
            );
            count += 1;
        }
    }
    eprintln!(
        "network guard: {count} actual Python pipeline operations across {} documents",
        scenarios.len()
    );
}
