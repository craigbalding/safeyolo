use safeyolo_proxy::circuits::*;
use serde_json::{Value, json};

fn config(cb: &CircuitBreaker, hash: &str, settings: Value) {
    assert!(
        cb.apply_sensor_config(&json!({"policy_hash":hash,"addons":{"circuit_breaker":settings}}))
            .unwrap()
    );
}
fn middle() -> f64 {
    0.5
}

#[test]
fn transitions_and_half_open_admission_are_atomic_across_clones() {
    let cb = CircuitBreaker::new();
    config(
        &cb,
        "initial",
        json!({"failure_threshold":2,"timeout_seconds":10,"jitter_factor":0}),
    );
    assert_eq!(
        cb.record_success("api", 100., &mut middle)
            .unwrap()
            .value
            .failure_count,
        0.
    );
    assert_eq!(cb.snapshot(100.).unwrap()["states"], json!({}));
    cb.record_failure("api", Some("HTTP 500"), 100., &mut middle)
        .unwrap();
    let opened = cb
        .record_failure("api", Some("HTTP 429"), 100., &mut middle)
        .unwrap();
    assert_eq!(opened.value.state, State::Open);
    assert_eq!(opened.events[0].event, TransitionKind::Open);
    let blocked = cb
        .request("api", RequestGate::default(), 100., &mut middle)
        .unwrap();
    let RequestDecision::Blocked {
        retry_after_seconds,
        ..
    } = blocked.value
    else {
        panic!("expected circuit block")
    };
    assert_eq!(retry_after_seconds.as_i64(), Some(10));
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(32));
    let admitted = std::thread::scope(|scope| {
        let tasks: Vec<_> = (0..32)
            .map(|_| {
                let cb = cb.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    cb.admit("api", 110., &mut middle).unwrap()
                })
            })
            .collect();
        let results: Vec<_> = tasks.into_iter().map(|task| task.join().unwrap()).collect();
        assert_eq!(
            results
                .iter()
                .flat_map(|result| &result.events)
                .filter(|event| event.event == TransitionKind::HalfOpen)
                .count(),
            1
        );
        results.into_iter().filter(|result| result.value.0).count()
    });
    assert_eq!(admitted, 3);
    assert_eq!(
        cb.record_success("api", 111., &mut middle)
            .unwrap()
            .value
            .state,
        State::HalfOpen
    );
    assert!(
        !cb.admit("api", 111., &mut middle).unwrap().value.0,
        "one success does not release a half-open attempt"
    );
    let recovered = cb.record_success("api", 112., &mut middle).unwrap();
    assert_eq!(recovered.value.state, State::Closed);
    assert_eq!(recovered.value.failure_count, 0.);
    assert_eq!(recovered.events[0].event, TransitionKind::Close);
    let stats = cb.stats(true, 112., &mut middle).unwrap().value;
    assert_eq!(stats["opens_total"], 1);
    assert_eq!(stats["half_opens_total"], 1);
    assert_eq!(stats["recoveries_total"], 1);
}

#[test]
fn jitter_draws_on_each_status_and_decay_uses_strict_truthy_timestamp() {
    let cb = CircuitBreaker::new();
    config(
        &cb,
        "jitter",
        json!({"timeout_seconds":10,"max_timeout_seconds":30,"jitter_factor":0.5,"streak_decay_seconds":100}),
    );
    assert_eq!(
        cb.settings()
            .unwrap()
            .calculate_timeout(100, &mut || 1.)
            .unwrap(),
        45.,
        "jitter is added after the cap"
    );
    assert_eq!(
        cb.settings()
            .unwrap()
            .calculate_timeout(0, &mut || panic!("no draw at streak zero"))
            .unwrap(),
        10.
    );
    cb.restore(&json!({"states":{"api":{"state":"closed","failure_count":2,"failure_streak":4,"last_failure_time":100}}}),150.,&mut middle).unwrap();
    let mut draws = 0;
    let success = cb
        .record_success("api", 150., &mut || {
            draws += 1;
            if draws == 1 { 0. } else { 1. }
        })
        .unwrap();
    assert_eq!(draws, 2);
    assert_eq!(success.value.current_timeout, 30.);
    assert_eq!(
        cb.status("api", 200., &mut middle)
            .unwrap()
            .value
            .failure_streak,
        1
    );
    assert_eq!(
        cb.status("api", 200.001, &mut || panic!(
            "decayed streak has no jitter"
        ))
        .unwrap()
        .value
        .failure_streak,
        0
    );
    cb.restore(
        &json!({"states":{"zero":{"state":"closed","failure_streak":2,"last_failure_time":0}}}),
        500.,
        &mut middle,
    )
    .unwrap();
    assert_eq!(
        cb.status("zero", 500., &mut middle)
            .unwrap()
            .value
            .failure_streak,
        1,
        "zero last_failure_time is falsy in Python"
    );
}

#[test]
fn hook_classification_preserves_exclusions_prior_blocks_and_missing_error_hook() {
    let cb = CircuitBreaker::new();
    config(&cb, "threshold", json!({"failure_threshold":1}));
    for host in ["localhost", "127.0.0.1", "_safeyolo.probe.internal"] {
        cb.force_open(host, 100.).unwrap();
        assert_eq!(
            cb.request(host, RequestGate::default(), 100., &mut middle)
                .unwrap()
                .value,
            RequestDecision::ExcludedDomain
        );
        assert_eq!(
            cb.response(
                host,
                ResponseInput {
                    enabled: true,
                    prior_block: false,
                    status: Some(503)
                },
                100.,
                &mut middle
            )
            .unwrap()
            .value,
            ResponseDecision::ExcludedDomain
        );
    }
    for status in [400, 401, 403, 404, 428, 499] {
        assert_eq!(
            cb.response(
                "api",
                ResponseInput {
                    enabled: true,
                    prior_block: false,
                    status: Some(status)
                },
                100.,
                &mut middle
            )
            .unwrap()
            .value,
            ResponseDecision::StatusNoAction
        );
    }
    assert_eq!(
        cb.response(
            "api",
            ResponseInput {
                enabled: true,
                prior_block: false,
                status: None
            },
            100.,
            &mut middle
        )
        .unwrap()
        .value,
        ResponseDecision::NoResponse
    );
    for status in [429, 500, 502, 599] {
        assert_eq!(
            cb.response(
                "api",
                ResponseInput {
                    enabled: true,
                    prior_block: true,
                    status: Some(status)
                },
                100.,
                &mut middle
            )
            .unwrap()
            .value,
            ResponseDecision::PriorBlock
        );
    }
    assert_eq!(
        cb.status("api", 100., &mut middle)
            .unwrap()
            .value
            .failure_count,
        0.
    );
    assert_eq!(
        cb.request(
            "api",
            RequestGate {
                policy_bypassed: true,
                ..Default::default()
            },
            100.,
            &mut middle
        )
        .unwrap()
        .value,
        RequestDecision::PolicyDisabled
    );
    // The response hook has no policy-bypass argument and still records the failure.
    assert_eq!(
        cb.response(
            "api",
            ResponseInput {
                enabled: true,
                prior_block: false,
                status: Some(429)
            },
            100.,
            &mut middle
        )
        .unwrap()
        .value,
        ResponseDecision::FailureRecorded
    );
    assert_eq!(
        cb.status("api", 100., &mut middle).unwrap().value.state,
        State::Open
    );
    assert_eq!(
        cb.response(
            "Localhost",
            ResponseInput {
                enabled: true,
                prior_block: false,
                status: Some(503)
            },
            100.,
            &mut middle
        )
        .unwrap()
        .value,
        ResponseDecision::FailureRecorded,
        "exclusions are exact case-sensitive strings"
    );
}

#[test]
fn configuration_reload_retains_omissions_exclusions_and_last_good_candidate() {
    let cb = CircuitBreaker::new();
    assert!(
        !cb.apply_sensor_config(&json!({"addons":{"circuit_breaker":{"failure_threshold":99}}}))
            .unwrap(),
        "initial empty hash is not a reload"
    );
    config(
        &cb,
        "one",
        json!({"failure_threshold":2.5,"timeout_seconds":15,"excluded_domains":["custom"]}),
    );
    assert!(
        !cb.apply_sensor_config(
            &json!({"policy_hash":"one","addons":{"circuit_breaker":{"failure_threshold":99}}})
        )
        .unwrap()
    );
    config(&cb, "two", json!({"jitter_factor":0,"excluded_domains":[]}));
    assert_eq!(cb.settings().unwrap().failure_threshold, 2.5);
    assert_eq!(cb.settings().unwrap().timeout_seconds, 15.);
    assert!(cb.settings().unwrap().excluded_domains.contains("custom"));
    cb.force_open("fraction", 100.).unwrap();
    assert_eq!(
        cb.record_failure("fraction", None, 100., &mut middle)
            .unwrap()
            .value
            .failure_count,
        3.5
    );
    assert!(
        cb.apply_sensor_config(
            &json!({"policy_hash":"three","addons":{"circuit_breaker":{"failure_threshold":null}}})
        )
        .is_err()
    );
    assert_eq!(cb.settings().unwrap().failure_threshold, 2.5);
    config(
        &cb,
        "three",
        json!({"use_exponential_backoff":false,"timeout_seconds":0,"half_open_max_requests":0,"failure_threshold":-1}),
    );
    cb.record_failure("zero", None, 100., &mut middle).unwrap();
    assert_eq!(
        cb.status("zero", 100., &mut middle).unwrap().value.state,
        State::HalfOpen
    );
    assert!(!cb.admit("zero", 100., &mut middle).unwrap().value.0);
}

#[test]
fn persistence_preserves_format_reconciles_and_reports_invalid_candidates() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state.json");
    let cb = CircuitBreaker::new();
    let snapshot = json!({"states":{
        "recent":{"state":"open","failure_count":7,"failure_streak":8,"opened_at":995,"last_failure_time":995,"manual_open":true,"future_field":{"kept":true}},
        "stale":{"state":"open","failure_count":5,"failure_streak":0,"opened_at":1},
        "closed":{"state":"closed","failure_count":1,"failure_streak":0}
    },"saved_at":995});
    std::fs::write(&path, snapshot.to_string()).unwrap();
    assert_eq!(
        cb.load_file(&path, 1000., &mut middle).unwrap().value,
        LoadDisposition::Loaded
    );
    let restored = cb.snapshot(1000.).unwrap();
    assert_eq!(restored["states"]["recent"]["failure_streak"], 1);
    assert_eq!(restored["states"]["recent"]["state"], "open");
    assert_eq!(
        restored["states"]["recent"]["future_field"],
        json!({"kept":true})
    );
    assert_eq!(restored["states"]["stale"]["state"], "half_open");
    assert_eq!(restored["states"]["stale"]["half_open_requests"], 0);
    assert!(
        !restored["states"]["closed"]
            .as_object()
            .unwrap()
            .contains_key("last_success_time")
    );
    cb.save_file(&path, 1001.).unwrap();
    let saved: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(saved, cb.snapshot(1001.).unwrap());
    std::fs::write(&path, r#"{"states":{"broken":{"state":"impossible"}}}"#).unwrap();
    assert!(cb.load_file(&path, 1002., &mut middle).is_err());
    assert_eq!(cb.snapshot(1001.).unwrap(), saved);
    std::fs::write(&path, "{broken").unwrap();
    assert_eq!(
        cb.load_file(&path, 1003., &mut middle).unwrap().value,
        LoadDisposition::DiscardedInvalidJson
    );
    assert_eq!(cb.snapshot(1003.).unwrap()["states"], json!({}));
    let missing = directory.path().join("missing.json");
    assert_eq!(
        cb.load_file(&missing, 1004., &mut middle).unwrap().value,
        LoadDisposition::Missing
    );
    let target = directory.path().join("directory");
    std::fs::create_dir(&target).unwrap();
    assert!(cb.save_file(&target, 1004.).is_err());
    assert!(std::fs::read_dir(directory.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".circuit-")
    }));
}

#[test]
fn manual_controls_keep_lifetime_statistics_and_reset_deletes_state() {
    let cb = CircuitBreaker::new();
    cb.force_open("api", 100.).unwrap();
    assert_eq!(
        cb.stats(true, 100., &mut middle).unwrap().value["opens_total"],
        0
    );
    cb.admit("api", 100., &mut middle).unwrap();
    assert_eq!(
        cb.reset("api").unwrap().events[0].event,
        TransitionKind::Reset
    );
    assert_eq!(
        cb.reset("unknown").unwrap().events[0].event,
        TransitionKind::Reset
    );
    let stats = cb.stats(false, 100., &mut middle).unwrap().value;
    assert_eq!(stats["enabled"], false);
    assert_eq!(stats["checks_total"], 1);
    assert_eq!(stats["domains"], json!({}));
}

fn operations() -> Vec<Value> {
    let mut ops = vec![
        json!({"op":"status","host":"unknown","now":100}),
        json!({"op":"success","host":"unknown","now":100}),
        json!({"op":"config","value":{"policy_hash":"one","addons":{"circuit_breaker":{"failure_threshold":2,"timeout_seconds":10,"max_timeout_seconds":30,"streak_decay_seconds":100,"jitter_factor":0.5,"excluded_domains":["custom"]}}}}),
        json!({"op":"admit","now":100}),
        json!({"op":"failure","now":100,"error":"HTTP 503"}),
        json!({"op":"success","now":100}),
        json!({"op":"failure","now":101,"error":"HTTP 429"}),
        json!({"op":"failure","now":102}),
        json!({"op":"request","now":105}),
        json!({"op":"admit","now":112}),
        json!({"op":"admit","now":112}),
        json!({"op":"admit","now":112}),
        json!({"op":"admit","now":112}),
        json!({"op":"success","now":113}),
        json!({"op":"request","now":113}),
        json!({"op":"failure","now":114}),
        json!({"op":"status","now":130,"random":[1]}),
        json!({"op":"status","now":130,"random":[0]}),
        json!({"op":"failure","now":131}),
        json!({"op":"status","now":160,"random":[1]}),
        json!({"op":"status","now":160,"random":[0]}),
        json!({"op":"success","now":161,"random":[0.1,0.9]}),
        json!({"op":"success","now":162}),
        json!({"op":"stats","now":163}),
        json!({"op":"force","now":164}),
        json!({"op":"request","now":165}),
        json!({"op":"reset","now":166}),
        json!({"op":"config","value":{"policy_hash":"one","addons":{"circuit_breaker":{"failure_threshold":99}}}}),
        json!({"op":"config","value":{"policy_hash":"two","addons":{"circuit_breaker":{"success_threshold":3,"excluded_domains":[]}}}}),
    ];
    for host in [
        "api",
        "localhost",
        "Localhost",
        "127.0.0.1",
        "_safeyolo.probe.internal",
        "_safeyolo.proxy.internal",
        "custom",
    ] {
        for (enabled, prior, policy) in [
            (true, false, false),
            (false, false, false),
            (true, true, false),
            (true, false, true),
        ] {
            ops.push(json!({"op":"request","host":host,"now":200,"enabled":enabled,"prior":prior,"policy":policy}));
        }
        for code in [
            Value::Null,
            json!(200),
            json!(302),
            json!(399),
            json!(400),
            json!(428),
            json!(429),
            json!(499),
            json!(500),
            json!(503),
            json!(599),
        ] {
            for (enabled, prior) in [(true, false), (false, false), (true, true)] {
                ops.push(json!({"op":"response","host":host,"now":200,"code":code,"enabled":enabled,"prior":prior}));
            }
        }
    }
    ops.extend([
        json!({"op":"restore","now":300,"value":{"states":{"recent":{"state":"open","opened_at":295,"failure_streak":9,"last_failure_time":295,"failure_count":8},"old":{"state":"open","opened_at":1,"failure_streak":3,"last_failure_time":1},"zero":{"state":"closed","failure_streak":8,"last_failure_time":0},"empty":{}}}}),
        json!({"op":"stats","now":301,"random":[0.1,0.9,0.3]}),json!({"op":"status","host":"recent","now":395}),json!({"op":"status","host":"recent","now":395.001}),
        json!({"op":"save","now":400}),json!({"op":"load","now":500}),json!({"op":"stats","now":500}),
        json!({"op":"config","value":{"policy_hash":"three","addons":{"circuit_breaker":{"failure_threshold":2.5,"success_threshold":1.5,"half_open_max_requests":2.5,"use_exponential_backoff":false,"timeout_seconds":0}}}}),
        json!({"op":"force","now":600}),json!({"op":"failure","now":600}),json!({"op":"admit","now":600}),json!({"op":"admit","now":600}),json!({"op":"admit","now":600}),json!({"op":"admit","now":600}),json!({"op":"success","now":600}),json!({"op":"success","now":600}),
    ]);
    ops.extend([
        json!({"op":"config","value":{"policy_hash":"large","addons":{"circuit_breaker":{"half_open_max_requests":1152921504606846976u64,"success_threshold":1152921504606846976u64}}}}),
        json!({"op":"restore","now":600,"value":{"states":{"api":{"state":"half_open","half_open_requests":1152921504606846975u64,"success_count":1152921504606846974u64}}}}),
        json!({"op":"admit","now":600}),json!({"op":"admit","now":600}),json!({"op":"success","now":600}),json!({"op":"success","now":600}),
    ]);
    ops.push(json!({"op":"stats","now":601}));
    for (index, settings) in [
        json!({"timeout_seconds":60,"max_timeout_seconds":300,"backoff_multiplier":2.0,"jitter_factor":0,"use_exponential_backoff":true}),
        json!({"jitter_factor":0.3}),json!({"backoff_multiplier":1.0}),json!({"backoff_multiplier":0.5}),
        json!({"backoff_multiplier":0.0}),json!({"backoff_multiplier":-2.0,"jitter_factor":-0.3}),
        json!({"backoff_multiplier":2.0,"timeout_seconds":10,"max_timeout_seconds":5}),
        json!({"use_exponential_backoff":false}),
    ].into_iter().enumerate() {
        ops.push(json!({"op":"config","value":{"policy_hash":format!("math-{index}"),"addons":{"circuit_breaker":settings}}}));
        for streak in [0,1,2,10,100] {
            for sample in [0.,0.5,1.] { ops.push(json!({"op":"timeout","streak":streak,"random":[sample],"now":700})); }
        }
    }
    ops
}

fn numerically_equal(actual: &Value, expected: &Value) -> bool {
    match (actual, expected) {
        (Value::Number(a), Value::Number(b)) => {
            let integer = |number: &serde_json::Number| -> Option<num_bigint::BigInt> {
                let spelling = number.to_string();
                if !spelling.contains(['.', 'e', 'E']) {
                    return spelling.parse().ok();
                }
                let value = number.as_f64()?;
                (value.fract() == 0.).then(|| format!("{value:.0}").parse().unwrap())
            };
            if let (Some(a), Some(b)) = (integer(a), integer(b)) {
                return a == b;
            }
            let a = a.as_f64().unwrap();
            let b = b.as_f64().unwrap();
            (a - b).abs() <= 1e-12 * a.abs().max(b.abs()).max(1.)
        }
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| numerically_equal(a, b))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter().all(|(key, value)| {
                    b.get(key)
                        .is_some_and(|other| numerically_equal(value, other))
                })
        }
        _ => actual == expected,
    }
}

#[test]
#[ignore = "historical Python transition oracle; set SAFEYOLO_POLICY_PYTHON"]
fn transitions_hooks_persistence_and_jitter_match_python() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let ops = operations();
    let script = r#"
import copy,dataclasses,json,pathlib,sys,tempfile
from unittest.mock import patch
from mitmproxy import http
from mitmproxy.test import tflow
from safeyolo.mitm_addons.circuit_breaker import CircuitBreaker,InMemoryCircuitState
cb=CircuitBreaker();cb.log_decision=lambda *a,**k:None
output=[]
def status(value):
    value=dataclasses.asdict(value);value['state']=value['state'].value;return value
with tempfile.TemporaryDirectory() as directory:
 path=pathlib.Path(directory)/'state.json'
 for op in json.load(sys.stdin):
    now=op.get('now',100);host=op.get('host','api');kind=op['op'];events=[];draws=[0];samples=op.get('random',[0.5])
    def uniform(a,b):
        value=samples[draws[0]%len(samples)];draws[0]+=1;return a+(b-a)*value
    cb._log_circuit_event=lambda name,domain,flow=None,**details:events.append({'event':name,'domain':domain,'details':details or None})
    with patch('safeyolo.mitm_addons.circuit_breaker.time.time',return_value=now),patch('safeyolo.mitm_addons.circuit_breaker.random.uniform',side_effect=uniform):
        if kind=='config':
            old=cb._last_policy_hash
            with patch('safeyolo.core.config_cache.get_or_raise',return_value=op['value']):cb._maybe_reload_config()
            value=old!=cb._last_policy_hash
        elif kind=='timeout':value=cb._calculate_timeout(op['streak'])
        elif kind=='status':value=status(cb.get_status(host))
        elif kind=='admit':
            allowed,state=cb.should_allow_request(host);value=[allowed,status(state)]
        elif kind=='failure':value=status(cb.record_failure(host,op.get('error')))
        elif kind=='success':value=status(cb.record_success(host))
        elif kind=='reset':cb.reset(host);value=None
        elif kind=='force':cb.force_open(host);value=None
        elif kind=='stats':
            cb.is_enabled=lambda:True;value=cb.get_stats()
        elif kind=='restore':
            cb._state._states=copy.deepcopy(op['value'].get('states',{}));cb._reconcile_stale_circuits();value=None
        elif kind=='save':
            cb._state._state_file=path;cb._state._save_state();value=None
        elif kind=='load':
            with patch.object(InMemoryCircuitState,'_start_snapshots'):
                cb._state=InMemoryCircuitState(path)
            cb._reconcile_stale_circuits();value='loaded'
        elif kind=='request':
            flow=tflow.tflow();flow.request.host=host
            if op.get('prior',False):flow.response=http.Response.make(403)
            enabled=op.get('enabled',True);cb.is_enabled=lambda:enabled
            cb.is_bypassed=lambda flow:bool(flow.response) or op.get('policy',False)
            observed=[];original=cb.should_allow_request
            def admit(domain):
                result=original(domain);observed.append(result);return result
            blocked=[]
            def block(flow,code,body,extra_headers=None):blocked.append((code,body,extra_headers))
            with patch.object(cb,'should_allow_request',side_effect=admit),patch.object(cb,'block',side_effect=block):cb.request(flow)
            if not enabled:value={'outcome':'addon_disabled'}
            elif op.get('prior',False):value={'outcome':'prior_response'}
            elif op.get('policy',False):value={'outcome':'policy_disabled'}
            elif host in cb._excluded_domains:value={'outcome':'excluded_domain'}
            else:
                allowed,state=observed[0];value={'outcome':'allowed' if allowed else 'blocked','status':status(state)}
                if not allowed:
                    code,body,headers=blocked[0];assert code==503;assert headers=={'Retry-After':str(body['retry_after_seconds']),'X-Circuit-State':state.state.value}
                    value['retry_after_seconds']=body['retry_after_seconds']
        elif kind=='response':
            flow=tflow.tflow();flow.request.host=host
            if op['code'] is not None:flow.response=http.Response.make(op['code'])
            if op.get('prior',False):flow.metadata['blocked_by']='other-addon'
            enabled=op.get('enabled',True);cb.is_enabled=lambda:enabled
            observed=[]
            with patch.object(cb,'_trace_evaluated',side_effect=lambda flow,**details:observed.append(details['outcome'])):cb.response(flow)
            value='addon_disabled' if not enabled else observed[-1] if observed else 'no_response'
        else:raise AssertionError(kind)
    output.append({'value':value,'events':copy.deepcopy(events),'snapshot':{'states':copy.deepcopy(cb._state._states),'saved_at':now},'draws':draws[0]})
json.dump(output,sys.stdout)
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
    let input = serde_json::to_vec(&ops).unwrap();
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
    let cb = CircuitBreaker::new();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state.json");
    for (index, op) in ops.iter().enumerate() {
        let now = op["now"].as_f64().unwrap_or(100.);
        let host = op["host"].as_str().unwrap_or("api");
        let kind = op["op"].as_str().unwrap();
        let samples = op.get("random").cloned().unwrap_or(json!([0.5]));
        let samples = samples.as_array().unwrap();
        let mut draws = 0;
        let mut random = || {
            let value = samples[draws % samples.len()].as_f64().unwrap();
            draws += 1;
            value
        };
        let result: Value = match kind {
            "config" => serde_json::to_value(Outcome {
                value: cb.apply_sensor_config(&op["value"]).unwrap(),
                events: vec![],
            })
            .unwrap(),
            "timeout" => {
                json!({"value":cb.settings().unwrap().calculate_timeout(op["streak"].as_i64().unwrap(),&mut random).unwrap(),"events":[]})
            }
            "status" => serde_json::to_value(cb.status(host, now, &mut random).unwrap()).unwrap(),
            "admit" => serde_json::to_value(cb.admit(host, now, &mut random).unwrap()).unwrap(),
            "failure" => serde_json::to_value(
                cb.record_failure(host, op["error"].as_str(), now, &mut random)
                    .unwrap(),
            )
            .unwrap(),
            "success" => {
                serde_json::to_value(cb.record_success(host, now, &mut random).unwrap()).unwrap()
            }
            "reset" => serde_json::to_value(cb.reset(host).unwrap()).unwrap(),
            "force" => serde_json::to_value(cb.force_open(host, now).unwrap()).unwrap(),
            "stats" => serde_json::to_value(cb.stats(true, now, &mut random).unwrap()).unwrap(),
            "restore" => {
                serde_json::to_value(cb.restore(&op["value"], now, &mut random).unwrap()).unwrap()
            }
            "save" => {
                cb.save_file(&path, now).unwrap();
                json!({"value":null,"events":[]})
            }
            "load" => serde_json::to_value(cb.load_file(&path, now, &mut random).unwrap()).unwrap(),
            "request" => serde_json::to_value(
                cb.request(
                    host,
                    RequestGate {
                        enabled: op["enabled"].as_bool().unwrap_or(true),
                        prior_response: op["prior"].as_bool().unwrap_or(false),
                        policy_bypassed: op["policy"].as_bool().unwrap_or(false),
                    },
                    now,
                    &mut random,
                )
                .unwrap(),
            )
            .unwrap(),
            "response" => serde_json::to_value(
                cb.response(
                    host,
                    ResponseInput {
                        enabled: op["enabled"].as_bool().unwrap_or(true),
                        prior_block: op["prior"].as_bool().unwrap_or(false),
                        status: op["code"].as_u64().map(|value| value as u16),
                    },
                    now,
                    &mut random,
                )
                .unwrap(),
            )
            .unwrap(),
            _ => panic!("unknown op {kind}"),
        };
        let actual = json!({"value":result["value"],"events":result["events"],"snapshot":cb.snapshot(now).unwrap(),"draws":draws});
        assert!(
            numerically_equal(&actual, &expected[index]),
            "operation {index} {op}\nnative={actual}\npython={}",
            expected[index]
        );
    }
    eprintln!(
        "Compared {} circuit operations, snapshots, transitions and exact jitter draw counts to Python",
        ops.len()
    );
}

#[test]
fn integers_are_not_silently_rounded_before_decisions_or_persistence() {
    let cb = CircuitBreaker::new();
    let bad = json!({"policy_hash":"bad","addons":{"circuit_breaker":{"failure_threshold":9007199254740993u64}}});
    assert!(cb.apply_sensor_config(&bad).is_err());
    assert_eq!(cb.settings().unwrap().failure_threshold, 5.);
    config(
        &cb,
        "exact",
        json!({"failure_threshold":9007199254740992u64}),
    );
    cb.force_open("large", 100.).unwrap();
    let before = cb.snapshot(100.).unwrap();
    assert_eq!(
        before["states"]["large"]["failure_count"].as_u64(),
        Some(9007199254740992)
    );
    assert!(cb.record_failure("large", None, 100., &mut middle).is_err());
    assert_eq!(cb.snapshot(100.).unwrap(), before);
    assert!(
        cb.restore(
            &json!({"states":{"bad":{"failure_count":9007199254740993u64}}}),
            100.,
            &mut middle
        )
        .is_err()
    );
    assert_eq!(cb.snapshot(100.).unwrap(), before);
}

#[test]
fn large_exact_slot_counts_compare_without_float_rounding() {
    let cb = CircuitBreaker::new();
    config(
        &cb,
        "large",
        json!({"half_open_max_requests":1152921504606846976u64,"success_threshold":1152921504606846976u64}),
    );
    cb.restore(&json!({"states":{"api":{"state":"half_open","half_open_requests":1152921504606846975u64,"success_count":1152921504606846974u64}}}),100.,&mut middle).unwrap();
    assert!(cb.admit("api", 100., &mut middle).unwrap().value.0);
    assert!(!cb.admit("api", 100., &mut middle).unwrap().value.0);
    assert_eq!(
        cb.record_success("api", 100., &mut middle)
            .unwrap()
            .value
            .state,
        State::HalfOpen
    );
    assert_eq!(
        cb.record_success("api", 100., &mut middle)
            .unwrap()
            .value
            .state,
        State::Closed
    );
    config(&cb, "long", json!({"timeout_seconds":1e30}));
    cb.force_open("slow", 100.).unwrap();
    let RequestDecision::Blocked {
        retry_after_seconds,
        ..
    } = cb
        .request("slow", RequestGate::default(), 100., &mut middle)
        .unwrap()
        .value
    else {
        panic!("expected circuit block")
    };
    assert_eq!(
        retry_after_seconds.to_string(),
        "1000000000000000019884624838656"
    );
}
