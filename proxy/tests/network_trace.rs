//! Reached NetworkGuard trace observations; no store or transport is installed.

use std::{
    cell::RefCell,
    io::Write,
    process::{Command, Stdio},
};

use safeyolo_proxy::{
    network_guard::{GuardError, Identity, NetworkGuard, Options, OutcomeKind, Pdp, Request},
    policy::{Format, Policy},
};
use serde_json::{Value, json};

fn request(method: &str) -> Request<'_> {
    Request {
        identity: Identity::Resolved("alice"),
        host: "owned.invalid",
        decode_ace_for_inspection: false,
        port: 443,
        method,
        path: "/owned",
        scheme: "https",
        request_id: Some("owned-request"),
        connection_id: "owned-connection",
        prior_response: false,
    }
}

fn cases() -> Vec<Value> {
    let mut rows = Vec::new();
    for (name, method, effect, block, fail) in [
        ("get_allow", "GET", "allow", true, false),
        ("connect_allow", "CONNECT", "allow", true, false),
        ("connect_allow_submit_error", "CONNECT", "allow", true, true),
        ("get_deny", "GET", "deny", true, false),
        ("connect_deny", "CONNECT", "deny", true, false),
        ("get_warn", "GET", "deny", false, false),
        ("get_deny_submit_error", "GET", "deny", true, true),
        ("get_warn_submit_error", "GET", "deny", false, true),
        ("get_prompt", "GET", "prompt", true, false),
    ] {
        rows.push(json!({"name":name,"method":method,"effect":effect,"block":block,"fail":fail,"bypass":null}));
    }
    for bypass in ["addon_disabled", "prior_response", "policy_disabled"] {
        rows.push(json!({"name":bypass,"method":"GET","effect":"deny","block":true,"fail":false,"bypass":bypass}));
    }
    rows
}

fn document(row: &Value) -> Value {
    let mut document =
        json!({"permissions":[{"action":"network:request","resource":"*","effect":row["effect"]}]});
    if row["bypass"] == "policy_disabled" {
        document["addons"] = json!({"network_guard":{"enabled":false}});
    }
    document
}

fn native(row: &Value) -> Value {
    let policy = Policy::parse(&document(row).to_string(), Format::Json).unwrap();
    let guard = NetworkGuard::new();
    let mut req = request(row["method"].as_str().unwrap());
    req.prior_response = row["bypass"] == "prior_response";
    let options = Options {
        enabled: row["bypass"] != "addon_disabled",
        block: row["block"].as_bool().unwrap(),
        ..Options::default()
    };
    let timeline = RefCell::new(Vec::new());
    let result = guard.enforce_with_audit_and_trace(
        Pdp::Ready(&policy),
        req,
        options,
        1000.,
        |intent| {
            timeline.borrow_mut().push(
                json!({"audit":intent.decision,"stats":guard.stats_json(options.enabled).unwrap()}),
            );
            if row["fail"] == true {
                Err(GuardError("owned submission failure".into()))
            } else {
                Ok(())
            }
        },
        |intent| {
            timeline
                .borrow_mut()
                .push(json!({"trace":intent,"stats":guard.stats_json(options.enabled).unwrap()}));
        },
    );
    if let Ok(outcome) = &result {
        let observed = timeline
            .borrow()
            .iter()
            .find_map(|item| item.get("trace").cloned())
            .unwrap();
        assert_eq!(observed, serde_json::to_value(&outcome.trace).unwrap());
    }
    json!({
        "failed":result.is_err(),
        "timeline":timeline.into_inner(),
        "stats":guard.stats_json(options.enabled).unwrap(),
        "evaluations":policy.engine_stats().unwrap()["evaluations"],
    })
}

#[test]
fn source_reached_points_order_observation_and_audit() {
    for row in cases() {
        let result = native(&row);
        let timeline = result["timeline"].as_array().unwrap();
        let names: Vec<_> = timeline
            .iter()
            .map(|item| {
                if item.get("trace").is_some() {
                    "trace"
                } else {
                    "audit"
                }
            })
            .collect();
        let expected = if row["bypass"].is_string() || row["name"] == "get_allow" {
            vec!["trace"]
        } else if row["method"] == "CONNECT" && row["effect"] == "allow" {
            vec!["trace", "audit"]
        } else if row["fail"] == true {
            vec!["audit"]
        } else {
            vec!["audit", "trace"]
        };
        assert_eq!(names, expected, "{}", row["name"]);
        assert_eq!(result["failed"], row["fail"]);
        assert_eq!(
            result["evaluations"],
            if row["bypass"].is_string() { 0 } else { 1 }
        );
        if row["name"] == "connect_allow_submit_error" {
            assert_eq!(timeline[0]["trace"]["outcome"], "allowed");
            assert_eq!(timeline[0]["stats"]["allowed"], 1);
        }
        if row["name"] == "get_deny_submit_error" || row["name"] == "get_warn_submit_error" {
            assert_eq!(result["stats"]["checks"], 1);
            assert_eq!(result["stats"]["blocked"], 0);
            assert_eq!(result["stats"]["warned"], 0);
        }
    }
}

#[test]
fn observation_keeps_single_budget_charge_and_no_step_for_pretrace_error() {
    let policy = Policy::parse(
        r#"{"permissions":[{"action":"network:request","resource":"*","effect":"budget","budget":1}]}"#,
        Format::Json,
    ).unwrap();
    let guard = NetworkGuard::new();
    // The source policy permits two reached requests for this declaration.
    // Observation must not add an evaluation/charge to either one.
    for expected in [
        OutcomeKind::Allowed,
        OutcomeKind::Allowed,
        OutcomeKind::Blocked,
    ] {
        let mut observed = None;
        let result = guard
            .enforce_with_audit_and_trace(
                Pdp::Ready(&policy),
                request("GET"),
                Options::default(),
                1000.,
                |_| Ok(()),
                |intent| {
                    assert!(observed.replace(intent.clone()).is_none());
                },
            )
            .unwrap();
        assert_eq!(result.kind, expected);
        assert_eq!(observed.unwrap(), result.trace);
    }
    assert_eq!(policy.engine_stats().unwrap()["evaluations"], 3);
    assert_eq!(guard.stats().unwrap().rate_limited, 1);
    let mut invalid = request("GET");
    invalid.port = 0;
    assert!(
        guard
            .enforce_with_audit_and_trace(
                Pdp::Ready(&policy),
                invalid,
                Options::default(),
                1000.,
                |_| panic!("pre-evaluation error must not submit audit"),
                |_| panic!("pre-evaluation error must not fabricate normal trace"),
            )
            .is_err()
    );
    assert_eq!(guard.stats().unwrap().checks, 4);
    assert_eq!(policy.engine_stats().unwrap()["evaluations"], 3);
}

#[test]
#[ignore = "requires existing Python production environment; set SAFEYOLO_POLICY_PYTHON"]
fn reached_network_trace_matches_actual_source_hooks() {
    let rows = cases();
    let input: Vec<_> = rows
        .iter()
        .map(|row| json!({"case":row,"document":document(row)}))
        .collect();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let script = r#"
import json
import logging
import pathlib
import sys
import tempfile
from unittest.mock import patch
from mitmproxy import ctx, http
from mitmproxy.test import taddons, tflow
from pdp.client import LocalPolicyClient, PolicyClientConfig
from safeyolo.mitm_addons.network_guard import NetworkGuard
from safeyolo.proxy_modes.unix_listener import UnixMode

logging.disable(logging.CRITICAL)
results = []
with patch('safeyolo.policy.loader.write_event'):
 for item in json.load(sys.stdin):
  row = item['case']
  with tempfile.TemporaryDirectory() as directory:
   path = pathlib.Path(directory) / 'policy.json'
   path.write_text(json.dumps(item['document']))
   client = LocalPolicyClient(PolicyClientConfig(baseline_path=path))
   client._pdp._engine._loader.stop_watcher()
   guard = NetworkGuard()
   timeline = []
   errors = []
   evaluations = []
   real_evaluate = client.evaluate
   def evaluate(event):
    evaluations.append(True)
    return real_evaluate(event)
   def step(flow, **kwargs):
    if kwargs['state'] == 'error':
     errors.append(kwargs['reason'])
     return
    intent = {key: kwargs.get(key) for key in ('hook', 'state', 'outcome', 'reason')}
    intent['status'] = (kwargs.get('details') or {}).get('status')
    timeline.append({'trace': intent, 'stats': guard.get_stats()})
   def submit(event, **kwargs):
    assert event == 'security.network_guard'
    timeline.append({'audit': kwargs['decision'], 'stats': guard.get_stats()})
    if row['fail']:
     raise RuntimeError('owned submission failure')
   with taddons.context(guard):
    ctx.options.update(network_guard_enabled=row['bypass'] != 'addon_disabled', network_guard_block=row['block'])
    flow = tflow.tflow()
    flow.client_conn.proxy_mode = UnixMode.parse('unix:/tmp/10.0.0.5_alice/proxy.sock')
    flow.request.host = 'owned.invalid'
    flow.request.port = 443
    flow.request.method = row['method']
    flow.request.path = '/owned'
    flow.request.scheme = 'https'
    flow.metadata.update(request_id='owned-request', trace=True)
    if row['bypass'] == 'prior_response':
     flow.response = http.Response.make(451, b'owned prior response')
    with patch('safeyolo.mitm_addons.network_guard.get_policy_client', return_value=client), patch('safeyolo.core.base.get_policy_client', return_value=client), patch.object(guard, '_resolve_service_discovery', return_value=None), patch.object(client, 'evaluate', side_effect=evaluate), patch('safeyolo.core.base.write_event', side_effect=submit), patch('safeyolo.core.base.record_step', side_effect=step), patch('safeyolo.core.trace.record_step', side_effect=step):
     failed = False
     try:
      if row['method'] == 'CONNECT':
       guard.http_connect(flow)
      else:
       guard.request(flow)
     except RuntimeError:
      failed = True
    # The native component supplies normal observations only; its runtime owns
    # terminal error classification. Preserve this explicit source distinction.
    assert errors == (['RuntimeError'] if row['fail'] else []), (row, errors)
    assert not any(key.startswith('_trace_hook_start:') for key in flow.metadata)
    results.append({'failed': failed, 'timeline': timeline, 'stats': guard.get_stats(), 'evaluations': len(evaluations)})
   client._pdp._engine.done()
json.dump(results, sys.stdout)
"#;
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
        .write_all(&serde_json::to_vec(&input).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(expected.len(), rows.len());
    for (row, expected) in rows.iter().zip(expected) {
        assert_eq!(native(row), expected, "{}", row["name"]);
    }
}
