use safeyolo_proxy::inspection::{
    Direction, ErrorKind, MAX_URL_SCAN_BYTES, MessageType, Options, Outcome, Scanner, UrlInput,
    compatibility_gaps,
};
use serde_json::{Value, json};

fn make_scanner(rules: Value) -> Scanner {
    let scanner = Scanner::default();
    scanner
        .load_policy_config(&json!({"scan_patterns":rules}))
        .unwrap();
    scanner
}
fn block() -> Options {
    Options {
        block_request: true,
        block_response: true,
        block_websocket_request: Some(true),
        block_websocket_response: Some(true),
    }
}
fn rule(name: &str, pattern: &str, scope: &str, action: &str) -> Value {
    json!({"name":name,"pattern":pattern,"scope":scope,"action":action})
}

#[test]
fn websocket_scans_complete_messages_in_each_direction_without_joining_messages() {
    let scanner = make_scanner(json!([rule("project", "PROJ-12345", "body", "block")]));
    for direction in [Direction::Request, Direction::Response] {
        for kind in [MessageType::Text, MessageType::Binary] {
            let result = scanner
                .scan_websocket_bytes(direction, kind, b"PROJ-12345", block())
                .unwrap();
            assert!(result.drop_message);
            assert_eq!(result.status, None);
            assert_eq!(result.finding.unwrap().message_type, Some(kind));
        }
    }
    for part in [b"PROJ-".as_slice(), b"12345".as_slice()] {
        assert_eq!(
            scanner
                .scan_websocket_bytes(Direction::Request, MessageType::Text, part, block())
                .unwrap()
                .outcome,
            Outcome::NoMatch
        )
    }
    let mut large = vec![b'x'; 2 * 1024 * 1024];
    large.extend_from_slice(b"PROJ-12345");
    assert!(
        scanner
            .scan_websocket_bytes(Direction::Request, MessageType::Text, &large, block())
            .unwrap()
            .drop_message
    );
    assert!(
        scanner
            .scan_websocket_text(
                Direction::Response,
                MessageType::Text,
                "PROJ-12345",
                block()
            )
            .unwrap()
            .drop_message
    );
}

#[test]
fn websocket_no_rules_bypasses_decoding_but_inspection_failures_drop_even_in_log_mode() {
    let scanner = Scanner::default();
    assert_eq!(
        scanner
            .scan_websocket_bytes(
                Direction::Request,
                MessageType::Text,
                b"\xff",
                Options::default()
            )
            .unwrap()
            .outcome,
        Outcome::NoRules
    );
    assert_eq!(
        scanner
            .scan_websocket_bytes(Direction::Response, MessageType::Other, b"x", block())
            .unwrap()
            .outcome,
        Outcome::NoRules
    );
    scanner
        .load_policy_config(&json!({"scan_patterns":[rule("body","nomatch","body","log")]}))
        .unwrap();
    let result = scanner
        .scan_websocket_bytes(
            Direction::Request,
            MessageType::Text,
            b"\xffpayload-not-evidence",
            Options::default(),
        )
        .unwrap();
    assert!(result.drop_message);
    assert_eq!(result.error_type, Some("UnicodeDecodeError"));
    assert_eq!(scanner.stats().unwrap().scans_total, 0);
    assert_eq!(
        scanner
            .scan_websocket_bytes(
                Direction::Request,
                MessageType::Other,
                b"payload",
                Options::default()
            )
            .unwrap()
            .error_type,
        Some("ValueError")
    );
    assert!(!format!("{result:?}").contains("payload-not-evidence"));
    assert!(
        !serde_json::to_string(&result)
            .unwrap()
            .contains("payload-not-evidence")
    );
}

#[test]
fn binary_maps_each_byte_to_latin1_and_text_requires_utf8() {
    let scanner = make_scanner(json!([rule("latin", "ÿ", "body", "block")]));
    assert!(
        scanner
            .scan_websocket_bytes(Direction::Request, MessageType::Binary, b"\xff", block())
            .unwrap()
            .drop_message
    );
    assert!(
        scanner
            .scan_websocket_text(Direction::Request, MessageType::Binary, "ÿ", block())
            .unwrap()
            .drop_message
    );
    assert_eq!(
        scanner
            .scan_websocket_bytes(Direction::Request, MessageType::Text, b"\xff", block())
            .unwrap()
            .error_type,
        Some("UnicodeDecodeError")
    );
    assert_eq!(
        scanner
            .scan_websocket_bytes(
                Direction::Request,
                MessageType::Binary,
                "ÿ".as_bytes(),
                block()
            )
            .unwrap()
            .outcome,
        Outcome::NoMatch
    );
    let scanner = make_scanner(json!([rule("empty", "^$", "body", "log")]));
    assert_eq!(
        scanner
            .scan_websocket_bytes(Direction::Request, MessageType::Text, b"", block())
            .unwrap()
            .outcome,
        Outcome::MatchLogged
    );
    assert_eq!(
        scanner
            .scan_http_request(UrlInput::Text("/"), &[], Some(""), block())
            .unwrap()
            .outcome,
        Outcome::NoMatch
    );
}

#[test]
fn independent_modes_preserve_legacy_missing_option_fallback_and_log_rule_precedence() {
    let scanner = make_scanner(json!([
        rule("first", "MATCH", "body", "log"),
        rule("second", "MATCH", "body", "block")
    ]));
    let result = scanner
        .scan_websocket_text(Direction::Request, MessageType::Text, "MATCH", block())
        .unwrap();
    assert_eq!(result.outcome, Outcome::MatchLogged);
    assert_eq!(result.finding.unwrap().rule_name, "first");
    let scanner = make_scanner(json!([rule("block", "MATCH", "body", "block")]));
    let mut options = Options {
        block_request: true,
        ..Options::default()
    };
    assert!(
        !scanner
            .scan_websocket_text(Direction::Request, MessageType::Text, "MATCH", options)
            .unwrap()
            .drop_message
    );
    options.block_websocket_request = None;
    assert!(
        scanner
            .scan_websocket_text(Direction::Request, MessageType::Text, "MATCH", options)
            .unwrap()
            .drop_message
    );
    options.block_request = false;
    options.block_websocket_request = Some(true);
    assert!(
        scanner
            .scan_websocket_text(Direction::Request, MessageType::Text, "MATCH", options)
            .unwrap()
            .drop_message
    );
    assert_eq!(
        scanner
            .scan_http_request(UrlInput::Text("/"), &[], Some("MATCH"), options)
            .unwrap()
            .outcome,
        Outcome::MatchLogged
    );
}

#[test]
fn http_scope_order_precedes_rule_order_but_url_forms_preserve_rule_precedence() {
    let scanner = make_scanner(json!([
        rule("body-first", "BODY", "body", "block"),
        rule("header", "HEAD", "headers", "block"),
        rule("decoded-first", "a=b", "url", "log"),
        rule("raw-second", "a%3Db", "url", "block")
    ]));
    let result = scanner
        .scan_http_request(
            UrlInput::Text("/?a%3Db"),
            &[("X-Header", "HEAD")],
            Some("BODY"),
            block(),
        )
        .unwrap();
    assert_eq!(result.outcome, Outcome::MatchLogged);
    assert_eq!(result.finding.unwrap().rule_name, "decoded-first");
    assert_eq!(scanner.stats().unwrap().scans_total, 2);
    assert_eq!(scanner.stats().unwrap().matches_total, 1);
    let result = scanner
        .scan_http_request(
            UrlInput::Text("/"),
            &[("X-First", "no"), ("X-Header", "HEAD")],
            Some("BODY"),
            block(),
        )
        .unwrap();
    assert_eq!(result.finding.unwrap().location, "header:X-Header");
    let result = scanner
        .scan_http_response(true, &[("X-Header", "HEAD")], Some("BODY"), block())
        .unwrap();
    assert_eq!(result.status, Some(502));
    assert_eq!(result.metadata["pattern_matched_response"], "header");
}

#[test]
fn urls_decode_once_keep_encoded_fragments_and_fail_closed_at_byte_bound() {
    let scanner = make_scanner(json!([rule("secret", "SECRET", "url", "block")]));
    for url in [
        "/%53ECRET",
        "/%53%45%43%52%45%54",
        "/?a=one&a=SECRET",
        "/%23SECRET",
    ] {
        assert_eq!(
            scanner
                .scan_http_request(UrlInput::Text(url), &[], None, Options::default())
                .unwrap()
                .outcome,
            Outcome::MatchLogged
        );
    }
    for url in ["/#SECRET", "/%2553ECRET", "/safe%", "/safe%2"] {
        assert_eq!(
            scanner
                .scan_http_request(UrlInput::Text(url), &[], None, block())
                .unwrap()
                .outcome,
            Outcome::NoMatch
        );
    }
    let exact = "x".repeat(MAX_URL_SCAN_BYTES);
    assert_eq!(
        scanner
            .scan_http_request(UrlInput::Text(&exact), &[], None, block())
            .unwrap()
            .outcome,
        Outcome::NoMatch
    );
    for url in [
        format!("{exact}x"),
        format!("#{}", exact),
        "é".repeat(MAX_URL_SCAN_BYTES / 2 + 1),
    ] {
        let result = scanner
            .scan_http_request(UrlInput::Text(&url), &[], None, Options::default())
            .unwrap();
        assert_eq!(result.status, Some(403));
        assert_eq!(result.failure, Some("url_inspection_overflow"));
        assert!(!serde_json::to_string(&result).unwrap().contains(&url));
    }
    assert_eq!(
        scanner
            .scan_http_request(UrlInput::Unavailable, &[], None, Options::default())
            .unwrap()
            .failure,
        Some("url_inspection_error")
    );
    let body_only = make_scanner(json!([rule("body", "SECRET", "body", "log")]));
    assert_eq!(
        body_only
            .scan_http_request(UrlInput::Unavailable, &[], None, block())
            .unwrap()
            .outcome,
        Outcome::NoMatch
    );
}

#[test]
fn path_bytes_preserve_surrogateescape_surrogatepass_expansion() {
    let scanner = make_scanner(json!([rule("replacement", "^/�{3}$", "url", "log")]));
    assert_eq!(
        scanner
            .scan_http_request(UrlInput::PathBytes(b"/\xff"), &[], None, block())
            .unwrap()
            .outcome,
        Outcome::MatchLogged
    );
    assert_eq!(
        scanner
            .scan_http_request(UrlInput::Bytes(b"/\xff"), &[], None, block())
            .unwrap()
            .outcome,
        Outcome::NoMatch
    );
    assert_eq!(
        scanner
            .scan_http_request(
                UrlInput::Bytes(&vec![0xff; MAX_URL_SCAN_BYTES]),
                &[],
                None,
                block()
            )
            .unwrap()
            .failure,
        Some("url_inspection_overflow")
    );
}

#[test]
fn reload_is_atomic_ordered_and_surfaces_engine_incompatibility_without_skipping_old_rules() {
    let scanner = Scanner::default();
    assert!(
        scanner
            .maybe_reload(Some(
                &json!({"scan_patterns":[rule("ignored-empty-hash","X","body","log")]})
            ))
            .unwrap()
            .is_none()
    );
    scanner
        .maybe_reload(Some(
            &json!({"policy_hash":"old","scan_patterns":[rule("old","OLD","body","block")]}),
        ))
        .unwrap()
        .unwrap();
    assert!(
        scanner
            .maybe_reload(Some(&json!({"policy_hash":"old","scan_patterns":[]})))
            .unwrap()
            .is_none()
    );
    let invalid = json!({"policy_hash":"new","scan_patterns":[rule("replace","NEW","body","block"),rule("unsupported",r"\N{LATIN CAPITAL LETTER A}","body","block")]});
    let failure = scanner.maybe_reload(Some(&invalid)).unwrap_err();
    assert_eq!(failure.kind, ErrorKind::RegexCompatibility);
    assert_eq!(failure.rule_index, Some(1));
    assert_eq!(
        scanner
            .scan_websocket_text(Direction::Request, MessageType::Text, "OLD", block())
            .unwrap()
            .finding
            .unwrap()
            .rule_name,
        "old"
    );
    assert!(!format!("{failure:?} {scanner:?}").contains("unsupported"));
    assert!(scanner.maybe_reload(None).unwrap().is_none());
    scanner
        .maybe_reload(Some(&json!({"policy_hash":"new","scan_patterns":[]})))
        .unwrap()
        .unwrap();
    assert!(!scanner.has_rules().unwrap());
    assert!(!compatibility_gaps().is_empty());
}

#[test]
fn skipped_configs_and_defaults_match_existing_loader_without_evidence_content() {
    let scanner = Scanner::default();
    let report=scanner.load_policy_config(&json!({"scan_patterns":[{}, {"name":"missing"},rule("danger",r"(.+)+SYNTHETIC-PATTERN","body","block"),rule("invalid","(unclosed-SYNTHETIC-PATTERN","body","block"),{"name":"kept\n\u{001b}[31m???a\u{0301}","pattern":"SYNTHETIC-CONTENT","scope":["invalid","BODY"],"target":"input","action":"invalid","severity":"invalid","case_sensitive":false,"message":"CUSTOM-MESSAGE-PRIVATE"}]})).unwrap();
    assert_eq!(report.rules_total, 1);
    assert_eq!(report.skipped.len(), 4);
    let result = scanner
        .scan_websocket_text(
            Direction::Request,
            MessageType::Text,
            "synthetic-content",
            block(),
        )
        .unwrap();
    assert_eq!(result.finding.as_ref().unwrap().rule_name, "kept?a?");
    assert_eq!(result.finding.as_ref().unwrap().pattern_action, "log");
    assert_eq!(result.finding.as_ref().unwrap().pattern_severity, "medium");
    let evidence = format!(
        "{result:?} {scanner:?} {report:?} {}",
        serde_json::to_string(&result).unwrap()
    );
    for private in [
        "SYNTHETIC-CONTENT",
        "synthetic-content",
        "SYNTHETIC-PATTERN",
        "CUSTOM-MESSAGE-PRIVATE",
    ] {
        assert!(!evidence.contains(private))
    }
    assert_eq!(
        scanner
            .scan_websocket_text(
                Direction::Response,
                MessageType::Text,
                "synthetic-content",
                block()
            )
            .unwrap()
            .outcome,
        Outcome::NoMatch
    );
}

#[test]
fn concurrent_scans_share_counts_and_use_one_complete_rules_snapshot() {
    let scanner = make_scanner(json!([rule("rule", "MATCH", "body", "block")]));
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let scanner = scanner.clone();
            scope.spawn(move || {
                for _ in 0..50 {
                    assert!(
                        scanner
                            .scan_websocket_text(
                                Direction::Request,
                                MessageType::Text,
                                "MATCH",
                                block()
                            )
                            .unwrap()
                            .drop_message
                    )
                }
            });
        }
    });
    let stats = scanner.stats().unwrap();
    assert_eq!(stats.scans_total, 400);
    assert_eq!(stats.matches_total, 400);
    assert_eq!(stats.blocks_total, 400);
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
        .write_all(serde_json::to_string(input).unwrap().as_bytes())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}

fn options(case: &Value) -> Options {
    Options {
        block_request: case["request_mode"].as_bool().unwrap_or(false),
        block_response: case["response_mode"].as_bool().unwrap_or(false),
        block_websocket_request: case["ws_request_mode"].as_bool(),
        block_websocket_response: case["ws_response_mode"].as_bool(),
    }
}
fn native_case(case: &Value) -> Value {
    let scanner = Scanner::default();
    scanner.load_policy_config(&case["config"]).unwrap();
    let direction = if case["direction"] == "response" {
        Direction::Response
    } else {
        Direction::Request
    };
    let mut headers: Vec<(String, String)> = Vec::new();
    for pair in case["headers"].as_array().unwrap() {
        let name = pair[0].as_str().unwrap();
        let value = pair[1].as_str().unwrap();
        if let Some((_, existing)) = headers
            .iter_mut()
            .find(|(existing, _)| existing.eq_ignore_ascii_case(name))
        {
            existing.push_str(", ");
            existing.push_str(value)
        } else {
            headers.push((name.into(), value.into()))
        }
    }
    let headers: Vec<_> = headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let ws = case["transport"] == "websocket";
    let decision = if ws {
        let payload: Vec<_> = case["payload"]
            .as_array()
            .unwrap()
            .iter()
            .map(|byte| byte.as_u64().unwrap() as u8)
            .collect();
        let kind = match case["kind"].as_str().unwrap() {
            "text" => MessageType::Text,
            "binary" => MessageType::Binary,
            _ => MessageType::Other,
        };
        scanner
            .scan_websocket_bytes(direction, kind, &payload, options(case))
            .unwrap()
    } else if direction == Direction::Response {
        scanner
            .scan_http_response(
                case["present"] != false,
                &headers,
                case["body"].as_str(),
                options(case),
            )
            .unwrap()
    } else {
        let bytes: Vec<_> = case["path_bytes"]
            .as_array()
            .map(|bytes| {
                bytes
                    .iter()
                    .map(|byte| byte.as_u64().unwrap() as u8)
                    .collect()
            })
            .unwrap_or_default();
        let path = if case["path_bytes"].is_array() {
            UrlInput::PathBytes(&bytes)
        } else {
            UrlInput::Text(case["path"].as_str().unwrap_or("/"))
        };
        scanner
            .scan_http_request(path, &headers, case["body"].as_str(), options(case))
            .unwrap()
    };
    let status = decision.status.unwrap_or(if ws {
        101
    } else if direction == Direction::Response && case["present"] != false || case["prior"] == true
    {
        200
    } else {
        0
    });
    json!({"metadata":decision.metadata,"status":status,"body":decision.body,"dropped":decision.drop_message,"finding":decision.finding,"error_type":decision.error_type,"stats":scanner.stats().unwrap()})
}
const PYTHON_SCANS: &str = r#"
import json,sys
from types import SimpleNamespace
from mitmproxy import http
from mitmproxy.test import tflow
from mitmproxy.websocket import WebSocketMessage
from wsproto.frame_protocol import Opcode
import safeyolo.mitm_addons.pattern_scanner as module
out=[]
for case in json.load(sys.stdin):
    owner=module.PatternScanner()
    owner.load_policy_config(case['config'])
    owner._maybe_reload_patterns=lambda:None
    opts=dict(pattern_block_request=case.get('request_mode',False),pattern_block_response=case.get('response_mode',False))
    for key,name in [('ws_request_mode','pattern_block_websocket_request'),('ws_response_mode','pattern_block_websocket_response')]:
        if case.get(key) is not None:opts[name]=case[key]
    module.ctx=SimpleNamespace(options=SimpleNamespace(**opts))
    audit=[]
    owner.log_decision=lambda *args,**kwargs:audit.append(kwargs)
    ws=case['transport']=='websocket'
    if ws:
        flow=tflow.twebsocketflow(messages=False)
        kind={'text':Opcode.TEXT,'binary':Opcode.BINARY,'other':Opcode.PING}[case['kind']]
        flow.websocket.messages=[WebSocketMessage(kind,case['direction']=='request',bytes(case['payload']))]
        flow.response=http.Response.make(101)
    else:
        flow=tflow.tflow()
        flow.request.content=case.get('body','').encode() if isinstance(case.get('body'),str) else None
        if 'path_bytes' in case:flow.request.data.path=bytes(case['path_bytes'])
        else:flow.request.path=case.get('path','/')
        flow.response=http.Response.make(200,case.get('body','').encode() if isinstance(case.get('body'),str) else b'') if (case['direction']=='response' and case.get('present',True)) or case.get('prior') else None
        flow.request.headers=http.Headers([(name.encode(),value.encode()) for name,value in case['headers']])
        if flow.response:flow.response.headers=http.Headers([(name.encode(),value.encode()) for name,value in case['headers']])
    flow.metadata={}
    if ws:owner.websocket_message(flow)
    elif case['direction']=='request':owner.request(flow)
    else:owner.response(flow)
    finding=None
    if audit and 'rule_name' in audit[-1]:finding={key:audit[-1][key] for key in ('direction','rule_name','rule_id','pattern_action','pattern_severity','location','message_type') if key in audit[-1]}
    out.append(dict(metadata={key:value for key,value in flow.metadata.items() if key.startswith(('pattern_','websocket_pattern_')) or key=='blocked_by'},status=flow.response.status_code if flow.response else 0,
        body=json.loads(flow.response.content) if flow.response and flow.metadata.get('blocked_by')=='pattern-scanner' else None,
        dropped=bool(ws and flow.websocket.messages[-1].dropped),finding=finding,error_type=audit[-1].get('error_type') if audit else None,stats=owner.get_stats()))
print(json.dumps(out))
"#;

#[test]
#[ignore = "Actual Python scanner HTTP/WS behavior; set SAFEYOLO_POLICY_PYTHON"]
fn python_http_websocket_modes_scope_order_and_failure_differential() {
    let mut cases = Vec::new();
    for target in ["request", "response", "both", "input", "output"] {
        for action in ["block", "log"] {
            for direction in ["request", "response"] {
                for kind in ["text", "binary"] {
                    for http_mode in [false, true] {
                        for ws_mode in [None, Some(false), Some(true)] {
                            cases.push(json!({"config":{"scan_patterns":[{"name":"project","pattern":"PROJ-12345","scope":["body"],"action":action,"target":target}]},"transport":"websocket","direction":direction,"kind":kind,"payload":b"PROJ-12345","headers":[],"request_mode":http_mode,"response_mode":http_mode,"ws_request_mode":ws_mode,"ws_response_mode":ws_mode}));
                        }
                    }
                }
            }
        }
    }
    for config in [
        json!({}),
        json!({"scan_patterns":[rule("body","MATCH","body","log")]}),
        json!({"scan_patterns":[rule("url-only","MATCH","url","log")]}),
    ] {
        for (kind, payload) in [
            ("text", vec![0xff]),
            ("binary", vec![0xff]),
            ("other", b"MATCH".to_vec()),
            ("text", vec![]),
        ] {
            cases.push(json!({"config":config,"transport":"websocket","direction":"request","kind":kind,"payload":payload,"headers":[]}));
        }
    }
    let rule_sets = [
        json!([]),
        json!([
            rule("body-first", "MATCH", "body", "block"),
            rule("header", "MATCH", "headers", "block"),
            rule("url-last", "MATCH", "url", "log")
        ]),
        json!([
            rule("first", "MATCH", "body", "log"),
            rule("second", "MATCH", "body", "block")
        ]),
        json!([{"name":"unusual\n???e\u{301}","pattern":"MATCH","scope":["BODY","HEADERS","URL"],"action":"unknown","severity":"unknown"}]),
    ];
    for rules in rule_sets {
        for direction in ["request", "response"] {
            for mode in [true, false] {
                for (path, headers, body) in [
                    ("/%4dATCH", json!([["X-Match", "MATCH"]]), Some("MATCH")),
                    (
                        "/",
                        json!([["X-First", "no"], ["X-Repeat", "MA"], ["x-repeat", "TCH"]]),
                        Some("MATCH"),
                    ),
                    ("/", json!([["X-First", "no"], ["X-\tName", "MATCH"]]), None),
                    ("/#MATCH", json!([]), Some("")),
                ] {
                    cases.push(json!({"config":{"scan_patterns":rules},"transport":"http","direction":direction,"path":path,"headers":headers,"body":body,"request_mode":mode,"response_mode":mode}));
                }
            }
        }
    }
    for path in [
        "x".repeat(MAX_URL_SCAN_BYTES + 1),
        "é".repeat(MAX_URL_SCAN_BYTES / 2),
        format!("#{}", "x".repeat(MAX_URL_SCAN_BYTES)),
        "/%254dATCH".into(),
        "/%23MATCH".into(),
        "/one+a=MATCH&a=no".into(),
    ] {
        cases.push(json!({"config":{"scan_patterns":[rule("url","MATCH","url","log")]},"transport":"http","direction":"request","path":path,"headers":[],"request_mode":false}));
    }
    for path_bytes in [
        vec![b'/', 0xff],
        vec![0xff; MAX_URL_SCAN_BYTES / 4],
        b"/%FF".to_vec(),
    ] {
        cases.push(json!({"config":{"scan_patterns":[rule("replacement","�{3}","url","log")]},"transport":"http","direction":"request","path_bytes":path_bytes,"headers":[]}));
    }
    cases.push(json!({"config":{"scan_patterns":[rule("body","MATCH","body","block")]},"transport":"http","direction":"request","prior":true,"headers":[],"body":"MATCH","request_mode":true}));
    cases.push(json!({"config":{"scan_patterns":[rule("body","MATCH","body","block")]},"transport":"http","direction":"response","present":false,"headers":[],"body":null}));
    let actual = python(PYTHON_SCANS, &json!(cases));
    for (case, actual) in cases.iter().zip(actual.as_array().unwrap()) {
        assert_eq!(native_case(case), *actual, "{case}");
    }
    eprintln!(
        "Compared {} actual Python HTTP/WS scan decisions, findings, metadata, failures and counts",
        cases.len()
    );
}

#[test]
#[ignore = "Actual Python builtin catalogue and specimen parity; set SAFEYOLO_POLICY_PYTHON"]
fn python_builtin_catalogue_order_and_detection_differential() {
    let builtins = python(
        "import json; from safeyolo.detection.patterns import BUILTIN_PATTERN_SETS; print(json.dumps(BUILTIN_PATTERN_SETS))",
        &Value::Null,
    );
    let source = include_str!("../src/inspection.rs");
    let snapshot = source
        .split("const BUILTINS: &str = r###\"")
        .nth(1)
        .unwrap()
        .split("\"###;")
        .next()
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(snapshot).unwrap(), builtins);
    let specimens = [
        ("openai-admin-key", format!("sk-admin-{}", "a".repeat(8))),
        ("openrouter-api-key", format!("sk-or-v1-{}", "a".repeat(20))),
        ("openai-api-key", format!("sk-proj-{}", "a".repeat(20))),
        (
            "anthropic-api-key",
            format!("sk-ant-api03-{}", "a".repeat(20)),
        ),
        ("github-pat", format!("ghp_{}", "a".repeat(36))),
        ("github-oauth", format!("gho_{}", "a".repeat(36))),
        ("github-app-user", format!("ghu_{}", "a".repeat(36))),
        ("github-app-server", format!("ghs_{}", "a".repeat(36))),
        ("github-refresh", format!("ghr_{}", "a".repeat(36))),
        (
            "github-fine-grained-pat",
            format!("github_pat_{}", "a".repeat(60)),
        ),
        ("google-api-key", format!("AIza{}", "a".repeat(35))),
        ("xai-api-key", format!("xai-{}", "a".repeat(20))),
        ("groq-api-key", format!("gsk_{}", "a".repeat(20))),
        ("huggingface-token", format!("hf_{}", "a".repeat(20))),
        ("ambiguous-sk-api-key", format!("sk-{}", "a".repeat(20))),
        ("aws-access-key", "AKIA0123456789ABCDEF".into()),
        // Exercise the marker pattern without committing key material or a
        // literal PEM opening delimiter that the repository secret hook flags.
        (
            "private-key",
            ["-----BEGIN RSA", "PRIVATE KEY-----"].join(" "),
        ),
        (
            "db-connection-string",
            "postgres://synthetic-user:synthetic-password@".into(),
        ),
        (
            "generic-bearer-in-body",
            format!("bearer {}", "a".repeat(20)),
        ),
        ("ssn-pattern", "123-45-6789".into()),
        ("credit-card", "4111111111111111".into()),
        ("email-address", "synthetic@example.invalid".into()),
    ];
    let mut cases = Vec::new();
    for (name, payload) in &specimens {
        for direction in ["request", "response"] {
            cases.push(json!({"config":{"addons":{"pattern_scanner":{"builtin_sets":["secrets","pii"]}},"scan_patterns":[rule("user-later",".","body","log")]},"transport":"websocket","direction":direction,"kind":"text","payload":payload.as_bytes(),"headers":[],"request_mode":true,"response_mode":true,"expected_name":name}));
        }
    }
    let actual = python(PYTHON_SCANS, &json!(cases));
    for (case, actual) in cases.iter().zip(actual.as_array().unwrap()) {
        let native = native_case(case);
        assert_eq!(native["finding"]["rule_name"], case["expected_name"]);
        assert_eq!(native, *actual, "{}", case["expected_name"]);
    }
    let scanner = Scanner::default();
    let report = scanner
        .load_policy_config(
            &json!({"addons":{"pattern_scanner":{"builtin_sets":["unknown","pii","pii"]}}}),
        )
        .unwrap();
    assert_eq!(report.rules_total, 6);
    assert_eq!(report.skipped.len(), 1);
    eprintln!(
        "Compared full builtin catalogue plus {} directional builtin specimens",
        cases.len()
    );
}

#[test]
#[ignore = "Python regex compatibility repairs and explicit remaining gaps; set SAFEYOLO_POLICY_PYTHON"]
fn python_regex_repairs_and_unresolved_engine_differences() {
    let samples = [
        (r"x\Z", "x\n"),
        (r"x\Z", "x"),
        (r"x$", "x\n"),
        (r"x$", "x\n\n"),
        (r"(?m)^x$", "x\nnext"),
        (r"(?x)x$ # \N comment", "x\n"),
        (r"(?# $ \N comment)x$", "x\n"),
        (r"[\s]", "\u{1c}"),
        (r"\S", "\u{1c}"),
        (r"\w", "\u{301}"),
        (r"\w", "²"),
        (r"\w", "Ⅸ"),
        (r"\bα\b", "α\u{301}"),
        (r"\B", ""),
        (r"\B", "!"),
        (r"\B", "ab"),
        (r"[[]", "["),
        (r"[a&&b]", "&"),
        (r"(?=secret)secret", "secret"),
        (r"(?<!a)b", "b"),
        (r"(?<=a)b", "ab"),
        (r"(a|b)\1", "bb"),
        (r"(?P<word>a)(?P=word)", "aa"),
        (r"(a)?(?(1)b|c)", "ab"),
        (r"(a)?(?(1)b|c)", "c"),
        (r"(?>a|ab)c", "abc"),
        (r"a++a", "aa"),
        (r"(?i:secret)", "SECRET"),
        (r"(?s)a.b", "a\nb"),
        (r"[\b]", "\u{8}"),
        (r"\\N", "\\N"),
    ];
    let input: Vec<_> = samples
        .iter()
        .map(|(pattern, text)| json!({"pattern":pattern,"text":text}))
        .collect();
    let actual = python(
        r#"
import json,sys
from safeyolo.detection.patterns import compile_pattern
out=[]
for case in json.load(sys.stdin):
    pattern=compile_pattern(case['pattern'])
    out.append(None if pattern is None else bool(pattern.search(case['text'])))
print(json.dumps(out))
"#,
        &json!(input),
    );
    for ((pattern, text), actual) in samples.iter().zip(actual.as_array().unwrap()) {
        let scanner = Scanner::default();
        scanner
            .load_policy_config(&json!({"scan_patterns":[rule("regex",pattern,"body","log")]}))
            .unwrap();
        let matched = scanner
            .scan_websocket_text(
                Direction::Request,
                MessageType::Text,
                text,
                Options::default(),
            )
            .unwrap()
            .finding
            .is_some();
        assert_eq!(json!(matched), *actual, "pattern {pattern:?} text {text:?}");
    }
    // Do not normalize these into agreement: they are retained-workflow gaps,
    // not permission to narrow policy. The module remains inactive.
    let unresolved = [(r"\N{LATIN CAPITAL LETTER A}", "A")];
    for (pattern, text) in unresolved {
        assert_eq!(
            python(
                "import json,re,sys; c=json.load(sys.stdin); print(json.dumps(bool(re.search(c['pattern'],c['text']))))",
                &json!({"pattern":pattern,"text":text})
            ),
            true
        );
        let scanner = Scanner::default();
        assert_eq!(
            scanner
                .load_policy_config(&json!({"scan_patterns":[rule("gap",pattern,"body","log")]}))
                .unwrap_err()
                .kind,
            ErrorKind::RegexCompatibility
        );
    }
    let scanner = make_scanner(json!([rule("casefold", r"(?i)^i$", "body", "log")]));
    assert_eq!(
        python(
            "import json,re; print(json.dumps(bool(re.search(r'(?i)^i$', 'İ'))))",
            &Value::Null
        ),
        true
    );
    assert_eq!(
        scanner
            .scan_websocket_text(
                Direction::Request,
                MessageType::Text,
                "İ",
                Options::default()
            )
            .unwrap()
            .outcome,
        Outcome::MatchLogged
    );
    assert!(!compatibility_gaps().is_empty());
    eprintln!(
        "Compared {} repaired/general Python regex cases; retained named-Unicode grammar gap",
        samples.len()
    );
}

#[test]
#[ignore = "Actual Python configuration reload and safe finding identities; set SAFEYOLO_POLICY_PYTHON"]
fn python_config_reload_rollback_and_evidence_identity_differential() {
    let configs = vec![
        json!({"scan_patterns":[rule("not-loaded-empty-hash","MATCH","body","log")]}),
        json!({"policy_hash":"one","scan_patterns":[{},rule("redos",r"(.+)+","body","log"),rule("invalid","[invalid","body","log"),{"name":"kept","pattern":"MATCH","scope":["UNKNOWN","BODY"],"target":"bad","action":"bad","severity":"bad","case_sensitive":null}]}),
        json!({"policy_hash":"one","scan_patterns":[]}),
        json!({"policy_hash":"bad","addons":[],"scan_patterns":[rule("new","MATCH","body","log")]}),
        json!({"policy_hash":"bad","scan_patterns":[{"name":"bad-target","pattern":"MATCH","target":[]}]}),
        json!({"policy_hash":"bad","scan_patterns":[{"name":"bad-scope","pattern":"MATCH","scope":[false]}]}),
        json!({"policy_hash":"bad","scan_patterns":[rule("replacement","MATCH","body","block")]}),
        Value::Null,
        json!({"policy_hash":"empty"}),
    ];
    let owner = Scanner::default();
    let mut expected = Vec::new();
    for config in &configs {
        let _ = owner.maybe_reload((!config.is_null()).then_some(config));
        let result = owner
            .scan_websocket_text(
                Direction::Request,
                MessageType::Text,
                "match MATCH",
                block(),
            )
            .unwrap();
        expected.push(json!({"stats":owner.stats().unwrap(),"metadata":result.metadata,"dropped":result.drop_message}));
    }
    let actual = python(
        r#"
import json,sys
from types import SimpleNamespace
from mitmproxy.test import tflow
from mitmproxy.websocket import WebSocketMessage
from wsproto.frame_protocol import Opcode
import safeyolo.mitm_addons.pattern_scanner as module
import safeyolo.core.config_cache as cache
owner=module.PatternScanner()
owner.log_decision=lambda *args,**kwargs:None
module.ctx=SimpleNamespace(options=SimpleNamespace(pattern_block_request=True))
out=[]
for config in json.load(sys.stdin):
    def get():
        if config is None:raise RuntimeError('synthetic config unavailable')
        return config
    cache.get_or_raise=get
    flow=tflow.twebsocketflow(messages=False)
    flow.metadata={}
    flow.websocket.messages=[WebSocketMessage(Opcode.TEXT,True,b'match MATCH')]
    owner.websocket_message(flow)
    out.append(dict(stats=owner.get_stats(),metadata={k:v for k,v in flow.metadata.items() if k.startswith('websocket_pattern_')},dropped=flow.websocket.messages[-1].dropped))
print(json.dumps(out))
"#,
        &json!(configs),
    );
    assert_eq!(actual, json!(expected));
    let names = [
        json!(true),
        json!(50),
        json!(["a'b", "line\n", null]),
        json!({"a":"line\n","b":[true,2]}),
        json!("\u{1b}[31mvery\n????long".repeat(40)),
        json!("e\u{301}x"),
    ];
    let cases:Vec<_>=names.into_iter().map(|name|json!({"config":{"scan_patterns":[{"name":name,"pattern":"MATCH","action":"log","severity":["bad"]}]},"transport":"websocket","direction":"request","kind":"text","payload":b"MATCH","headers":[]})).collect();
    let actual = python(PYTHON_SCANS, &json!(cases));
    for (case, actual) in cases.iter().zip(actual.as_array().unwrap()) {
        assert_eq!(native_case(case), *actual, "{}", case["config"]);
    }
    eprintln!(
        "Compared {} actual Python reload/configuration operations and {} bounded evidence identity cases",
        configs.len(),
        cases.len()
    );
}

#[test]
fn websocket_valid_large_message_retains_log_and_block_decisions() {
    let payload = "a".repeat(1_000_100);
    let pattern = r"(a|aa)*\1$";
    for action in ["log", "block"] {
        let scanner = make_scanner(json!([rule("large-message", pattern, "body", action)]));
        for direction in [Direction::Request, Direction::Response] {
            let decision = scanner
                .scan_websocket_text(direction, MessageType::Text, &payload, block())
                .unwrap();
            assert_eq!(
                decision.outcome,
                if action == "block" {
                    Outcome::MatchBlocked
                } else {
                    Outcome::MatchLogged
                }
            );
            assert_eq!(decision.drop_message, action == "block");
            assert_eq!(decision.error_type, None);
        }
    }
}

#[test]
#[ignore = "Actual Python/native complete-message stack regression; set SAFEYOLO_POLICY_PYTHON"]
fn python_large_complete_messages_match_after_native_stack_growth_repair() {
    let pattern = r"(a|aa)*\1$";
    for length in [1_000_100, 4_194_304, 8_388_608] {
        let payload = "a".repeat(length);
        let python_match = python(
            r#"
import json,sys
from safeyolo.detection.patterns import compile_pattern
value=json.load(sys.stdin)
pattern=compile_pattern(value['pattern'])
print(json.dumps(dict(accepted=pattern is not None,matched=bool(pattern.search(value['text'])))))
"#,
            &json!({"pattern":pattern,"text":payload}),
        );
        assert_eq!(python_match, json!({"accepted":true,"matched":true}));
        let scanner = make_scanner(json!([rule("growing-stack", pattern, "body", "log")]));
        let native = scanner
            .scan_websocket_text(
                Direction::Request,
                MessageType::Text,
                &payload,
                Options::default(),
            )
            .unwrap();
        assert_eq!(native.outcome, Outcome::MatchLogged);
        assert!(!native.drop_message);
        assert_eq!(native.error_type, None);
    }
    // Compilation, Python grammar and Unicode differences are separate work.
    assert!(
        compatibility_gaps().contains(&"regex_compilation_expansion_and_backtracking_resources")
    );
    eprintln!(
        "Python/native log-mode whole-message matches agree at 1,000,100, 4,194,304 and 8,388,608 bytes; remaining grammar/Unicode gaps still block activation"
    );
}

#[test]
fn websocket_precancellation_is_distinct_and_has_no_findings_or_counter_effects() {
    use std::sync::atomic::AtomicBool;
    let cancel = AtomicBool::new(true);
    for rules in [
        json!([]),
        json!([rule("body", "payload-not-evidence", "body", "block")]),
    ] {
        let scanner = make_scanner(rules);
        for kind in [MessageType::Text, MessageType::Binary, MessageType::Other] {
            let failure = scanner
                .scan_websocket_text_cancellable(
                    Direction::Request,
                    kind,
                    "payload-not-evidence",
                    block(),
                    &cancel,
                )
                .unwrap_err();
            assert_eq!(failure.kind, ErrorKind::Cancelled);
            assert_eq!(failure.rule_index, None);
            assert!(!format!("{failure:?}").contains("payload-not-evidence"));
            let stats = scanner.stats().unwrap();
            assert_eq!(
                (stats.scans_total, stats.matches_total, stats.blocks_total),
                (0, 0, 0)
            );
        }
    }
}

#[test]
fn websocket_running_scan_cancels_without_inspection_error_or_affecting_another_call() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    use std::time::{Duration, Instant};
    for action in ["log", "block"] {
        let scanner = Arc::new(make_scanner(json!([rule(
            "ambiguous",
            r"^(a|aa)*\1$",
            "body",
            action
        )])));
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_scanner = Arc::clone(&scanner);
        let worker_cancel = Arc::clone(&cancel);
        let (send, recv) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let text = format!("{}b", "a".repeat(4096));
            let result = worker_scanner.scan_websocket_text_cancellable(
                Direction::Request,
                MessageType::Text,
                &text,
                block(),
                &worker_cancel,
            );
            send.send(result).unwrap();
        });
        let until = Instant::now() + Duration::from_secs(2);
        while scanner.stats().unwrap().scans_total == 0 && Instant::now() < until {
            std::thread::yield_now();
        }
        // The vendor's Input-hook test separately proves cancellation inside VM
        // execution. This scanner test verifies counter/evidence propagation.
        let started = scanner.stats().unwrap().scans_total == 1;
        cancel.store(true, Ordering::Relaxed);
        let result = recv
            .recv_timeout(Duration::from_secs(2))
            .expect("cancelled scanner did not finish");
        worker.join().unwrap();
        assert!(started);
        assert_eq!(result.unwrap_err().kind, ErrorKind::Cancelled);
        let stats = scanner.stats().unwrap();
        assert_eq!((stats.matches_total, stats.blocks_total), (0, 0));
        let independent = AtomicBool::new(false);
        let ordinary = scanner
            .scan_websocket_text_cancellable(
                Direction::Response,
                MessageType::Binary,
                "aaaa",
                block(),
                &independent,
            )
            .unwrap();
        assert_eq!(
            ordinary.outcome,
            if action == "block" {
                Outcome::MatchBlocked
            } else {
                Outcome::MatchLogged
            }
        );
        assert!(cancel.load(Ordering::Relaxed));
    }
}

#[test]
fn uncancelled_websocket_api_preserves_decisions_including_no_rules_and_invalid_kind() {
    use std::sync::atomic::AtomicBool;
    let cancel = AtomicBool::new(false);
    for rules in [json!([]), json!([rule("body", "abcd", "body", "block")])] {
        let scanner = make_scanner(rules);
        for direction in [Direction::Request, Direction::Response] {
            for kind in [MessageType::Text, MessageType::Binary, MessageType::Other] {
                for text in ["abcd", "", "nomatch"] {
                    let ordinary = scanner
                        .scan_websocket_text(direction, kind, text, block())
                        .unwrap();
                    let cancellable = scanner
                        .scan_websocket_text_cancellable(direction, kind, text, block(), &cancel)
                        .unwrap();
                    assert_eq!(
                        serde_json::to_value(ordinary).unwrap(),
                        serde_json::to_value(cancellable).unwrap()
                    );
                }
            }
        }
    }
}

#[test]
fn ascii_scopes_and_octal_literals_keep_unicode_scalars_and_reference_boundaries() {
    for (pattern, text, expected) in [
        (r"(?a:^.$)", "é", true),
        (r"(?a:^\w$)", "é", false),
        (r"(?ai:^k$)", "K", false),
        (r"(?ai:^ä$)", "Ä", false),
        (r"(?ai:^ä$)", "ä", true),
        (r"(?ai:^[a-]$)", "-", true),
        (r"(?ai:^[^a-]$)", "-", false),
        (r"(?a:\w(?u:\w))", "aé", true),
        (r"(?a:(?u:\w)\w)", "éa", true),
        (r"(?ai:(ä)\1)", "äÄ", false),
        (r"(ä)(?ai:\1)(?i:\1)", "ääÄ", true),
        (r"\0", "\0", true),
        (r"\08", "\08", true),
        (r"\141", "a", true),
        (r"[\11]", "\t", true),
        (r"\1110", "I0", true),
    ] {
        let scanner = make_scanner(json!([rule("regex", pattern, "body", "log")]));
        let decision = scanner
            .scan_websocket_text(
                Direction::Request,
                MessageType::Text,
                text,
                Options::default(),
            )
            .unwrap();
        assert_eq!(
            decision.finding.is_some(),
            expected,
            "{pattern:?}, {text:?}"
        );
    }
    let pattern = format!("{}\\118", "(a)".repeat(12));
    let scanner = make_scanner(json!([rule("reference", &pattern, "body", "log")]));
    assert!(
        scanner
            .scan_websocket_text(
                Direction::Request,
                MessageType::Text,
                &format!("{}8", "a".repeat(13)),
                Options::default()
            )
            .unwrap()
            .finding
            .is_some()
    );
}

#[test]
fn python_invalid_ascii_flags_and_octal_escapes_cannot_enable_private_native_syntax() {
    for pattern in [
        r"(?A:a)",
        r"(?a:(?A:a))",
        r"(?au:a)",
        r"(?-a:a)",
        r"(?L:a)",
        r"\400",
        r"[\777]",
        r"[\8]",
        r"(a)\18",
    ] {
        let scanner = Scanner::default();
        let report = scanner
            .load_policy_config(&json!({"scan_patterns":[rule("invalid",pattern,"body","log")]}))
            .unwrap();
        assert_eq!(report.rules_total, 0, "{pattern}");
    }
    for pattern in [r"\(\?A:a\)", r"\050\077A:a\051"] {
        let scanner = make_scanner(json!([rule("literal", pattern, "body", "log")]));
        assert!(
            scanner
                .scan_websocket_text(
                    Direction::Request,
                    MessageType::Text,
                    "(?A:a)",
                    Options::default()
                )
                .unwrap()
                .finding
                .is_some()
        );
    }
    let scanner = make_scanner(json!([rule("retained", "keep", "body", "log")]));
    // These global combinations raise ValueError in Python, rather than re.error.
    assert_eq!(
        scanner
            .load_policy_config(
                &json!({"scan_patterns":[rule("invalid",r"(?a)(?u)a","body","log")]})
            )
            .unwrap_err()
            .kind,
        ErrorKind::RegexCompatibility
    );
    assert!(
        scanner
            .scan_websocket_text(
                Direction::Request,
                MessageType::Text,
                "keep",
                Options::default()
            )
            .unwrap()
            .finding
            .is_some()
    );
}

#[test]
fn configured_ascii_negative_categories_enforce_the_rule_despite_python_prefilter_defect() {
    for (pattern, text) in [(r"(?a:\W)", "é"), (r"(?a:\D)", "١"), (r"(?a:\S)", "\x1c")] {
        for action in ["log", "block"] {
            let scanner = make_scanner(json!([rule("non-ascii", pattern, "body", action)]));
            let decision = scanner
                .scan_websocket_text(Direction::Request, MessageType::Text, text, block())
                .unwrap();
            assert_eq!(
                decision.outcome,
                if action == "block" {
                    Outcome::MatchBlocked
                } else {
                    Outcome::MatchLogged
                }
            );
            assert_eq!(decision.finding.unwrap().rule_name, "non-ascii");
        }
    }
}

#[test]
fn python_unicode_categories_pin_python_312_scalar_membership() {
    // Python 3.12 ships Unicode 15.0. U+13460 is still unassigned there,
    // while newer Rust Unicode tables classify it as a letter. U+1E4F0 is a
    // Unicode-15 decimal digit. These witnesses keep native shorthand
    // categories tied to the source runtime rather than the build toolchain.
    let word = make_scanner(json!([rule("word", r"^\w$", "body", "block")]));
    for (text, expected) in [
        ("é", Outcome::MatchBlocked),
        ("²", Outcome::MatchBlocked),
        ("\u{13460}", Outcome::NoMatch),
        ("\u{301}", Outcome::NoMatch),
    ] {
        let result = word
            .scan_websocket_text(Direction::Request, MessageType::Text, text, block())
            .unwrap();
        assert_eq!(result.outcome, expected, "source category witness {text:?}");
        if expected == Outcome::MatchBlocked {
            assert_eq!(result.finding.unwrap().rule_name, "word");
        } else {
            assert!(result.finding.is_none());
        }
    }
    let decimal = make_scanner(json!([rule("decimal", r"^\d$", "body", "block")]));
    for (text, expected) in [
        ("١", Outcome::MatchBlocked),
        ("\u{1e4f0}", Outcome::MatchBlocked),
        ("²", Outcome::NoMatch),
        ("\u{13460}", Outcome::NoMatch),
    ] {
        let result = decimal
            .scan_websocket_text(Direction::Request, MessageType::Text, text, block())
            .unwrap();
        assert_eq!(result.outcome, expected, "source decimal witness {text:?}");
        if expected == Outcome::MatchBlocked {
            assert_eq!(result.finding.unwrap().rule_name, "decimal");
        } else {
            assert!(result.finding.is_none());
        }
    }
}

#[test]
fn d33_named_unicode_and_nesting_rows_fail_closed_with_supported_depth() {
    let named = Scanner::default();
    assert_eq!(
        named
            .load_policy_config(&json!({
                "scan_patterns": [rule(
                    "unicode-name",
                    r"^\N{LATIN CAPITAL LETTER A}$",
                    "body",
                    "log"
                )]
            }))
            .unwrap_err()
            .kind,
        ErrorKind::RegexCompatibility
    );

    let nested = format!("{}a{}", "(?:".repeat(8), ")".repeat(8));
    let scanner = make_scanner(json!([rule("nested", &nested, "body", "log")]));
    assert_eq!(
        scanner
            .scan_websocket_text(
                Direction::Request,
                MessageType::Text,
                "a",
                Options::default()
            )
            .unwrap()
            .outcome,
        Outcome::MatchLogged
    );

    // fancy-regex reports its parser recursion boundary as compatibility;
    // retaining that explicit failure is safer than accepting a different
    // grammar or silently dropping the source rule.
    let too_deep = format!("{}a{}", "(?:".repeat(64), ")".repeat(64));
    assert_eq!(
        Scanner::default()
            .load_policy_config(&json!({
                "scan_patterns": [rule("too-deep", &too_deep, "body", "log")]
            }))
            .unwrap_err()
            .kind,
        ErrorKind::RegexCompatibility
    );
}

fn source_prefilter_case(pattern: &str) -> bool {
    ["a", "ai", "a-i"].iter().any(|flags| {
        [r"\W", r"\D", r"\S", r"[^\w]", r"[\W]", r"[\W\D]"]
            .iter()
            .any(|atom| pattern == format!("(?{flags}:{atom})"))
    })
}
#[test]
#[ignore = "Actual Python scoped ASCII/octal matrix and intentional prefilter correction; set SAFEYOLO_POLICY_PYTHON"]
fn python_ascii_octal_matrix_keeps_source_defects_separate_from_remaining_gaps() {
    let patterns = ascii_octal_patterns();
    let texts = ascii_octal_subjects();
    let cases:Vec<_>=patterns.iter().map(|(pattern,insensitive)|json!({"pattern":pattern,"insensitive":insensitive,"texts":texts,"source_prefilter":source_prefilter_case(pattern)})).collect();
    let actual = python(
        r#"
import json,sys,re,contextlib,io
from safeyolo.detection.patterns import compile_pattern
out=[]
for case in json.load(sys.stdin):
    try:
        expression=compile_pattern(case['pattern'],case_sensitive=not case['insensitive'])
        row={'accepted':expression is not None}
        if expression is not None:
            row['matches']=[bool(expression.search(text))for text in case['texts']]
            if case['source_prefilter']:
                # A universally true assertion disables the incorrect INFO prefilter.
                guarded=re.compile('(?=)'+case['pattern'],re.I if case['insensitive']else 0)
                row['guarded']=[bool(guarded.search(text))for text in case['texts']]
                debug=io.StringIO()
                with contextlib.redirect_stdout(debug):re.compile(case['pattern'],(re.I if case['insensitive']else 0)|re.DEBUG)
                row['debug']=debug.getvalue()
        out.append(row)
    except ValueError:
        out.append({'accepted':False,'exception':'ValueError'})
print(json.dumps(out))
"#,
        &json!(cases),
    );
    let mut corrected = 0;
    let mut grammar_gaps = 0;
    for ((pattern, insensitive), old) in patterns.iter().zip(actual.as_array().unwrap()) {
        let scanner = Scanner::default();
        let mut config = rule("matrix", pattern, "body", "log");
        config["case_sensitive"] = json!(!insensitive);
        let loaded = scanner.load_policy_config(&json!({"scan_patterns":[config]}));
        let accepted = loaded.as_ref().is_ok_and(|report| report.rules_total == 1);
        if old["accepted"] == true && !accepted {
            assert_eq!(pattern, r"(?ai)\N{LATIN CAPITAL LETTER A}");
            assert_eq!(loaded.unwrap_err().kind, ErrorKind::RegexCompatibility);
            grammar_gaps += 1;
            continue;
        }
        assert_eq!(
            json!(accepted),
            old["accepted"],
            "acceptance {pattern:?}, insensitive={insensitive}"
        );
        if !accepted {
            continue;
        }
        let matches: Vec<_> = texts
            .iter()
            .map(|text| {
                scanner
                    .scan_websocket_text(
                        Direction::Request,
                        MessageType::Text,
                        text,
                        Options::default(),
                    )
                    .unwrap()
                    .finding
                    .is_some()
            })
            .collect();
        if json!(matches) == old["matches"] {
            continue;
        }
        if source_prefilter_case(pattern) {
            assert_eq!(
                json!(matches),
                old["guarded"],
                "prefilter correction {pattern:?}"
            );
            assert!(old["debug"].as_str().unwrap().contains("UNI_"));
            corrected += 1;
        } else {
            panic!("unclassified mismatch {pattern:?}");
        }
    }
    assert_eq!((corrected, grammar_gaps), (36, 1));
    eprintln!(
        "Compared {} patterns x {} subjects; 36 corrected Python prefilter rows, 1 retained named-Unicode grammar gap",
        patterns.len(),
        texts.len()
    );
}

fn ascii_octal_patterns() -> Vec<(String, bool)> {
    let mut patterns = Vec::new();
    for atom in [
        "\\w",
        "\\W",
        "\\d",
        "\\D",
        "\\s",
        "\\S",
        "\\b",
        "\\B",
        ".",
        "[^a]",
        "a",
        "A",
        "k",
        "K",
        "i",
        "s",
        "ä",
        "É",
        "α",
        "\\x41",
        "\\u00c4",
        "\\U000003b1",
        "[a-z]",
        "[^a-z]",
        "[A-ÿ]",
        "[^A-ÿ]",
        "[À-Ö]",
        "[\\w]",
        "[^\\w]",
        "[\\W]",
        "[^\\W]",
        "[\\s\\S]",
        "[a\\d]",
        "[[]",
        "[a&&b]",
        "[]a]",
        "[^]a]",
        "[\\0-\\177]",
        "[\\141-\\172]",
        "[a-]",
        "[-a]",
        "[^a-]",
        "[a\\-]",
        "[\\W\\D]",
        "[()A?:]",
    ] {
        for flags in ["a", "ai", "a-i", "u", "ui", "i", ""] {
            for insensitive in [false, true] {
                patterns.push((
                    if flags.is_empty() {
                        atom.to_string()
                    } else {
                        format!("(?{flags}:{atom})")
                    },
                    insensitive,
                ));
            }
        }
    }
    patterns.extend([
        ("(?a)\\w".to_string(),false),
        ("(?ai)ä".to_string(),false),
        ("(?a:(?u:\\w))".to_string(),false),
        ("(?ai:(?u:ä))".to_string(),false),
        ("(?ui:(?a:ä))".to_string(),false),
        ("(?i:(?a:k))".to_string(),false),
        ("(?a:(?i:k))".to_string(),false),
        ("(?ai:(?-i:k))".to_string(),false),
        ("(?ai:[k])(?u:k)".to_string(),false),
        ("(?a:(?u:\\w)\\w)".to_string(),false),
        ("(?a:\\w(?u:\\w))".to_string(),false),
        ("(?x) (?a: \\w #comment\\N\n )".to_string(),false),
        ("(?ax:\\w)\\w".to_string(),false),
        ("(?a:(?P<name>a)(?P=name))".to_string(),false),
        ("(?a:(a)\\1)".to_string(),false),
        ("(?ai:(a)\\1)".to_string(),false),
        ("(?ai:(ä)\\1)".to_string(),false),
        ("(?ai:(?P<name>ä)(?P=name))".to_string(),false),
        ("(?ai:(a)(?-i:\\1))".to_string(),false),
        ("(?a:(a)?(?(1)b|c))".to_string(),false),
        ("(?ai:(a)?(?(1)b|c))".to_string(),false),
        ("(?a)(?u)a".to_string(),false),
        ("(?u)(?a)a".to_string(),false),
        ("(?au:a)".to_string(),false),
        ("(?a-u:a)".to_string(),false),
        ("(?-a:a)".to_string(),false),
        ("(?L:a)".to_string(),false),
        ("(?ii:a)".to_string(),false),
        ("(?i-i:a)".to_string(),false),
        ("(?-:a)".to_string(),false),
        ("a(?i)b".to_string(),false),
        ("(?x) (?i)a".to_string(),false),
        ("(?# comment)(?i)a".to_string(),false),
        ("(?ai)\\N{LATIN CAPITAL LETTER A}".to_string(),false),
        ("(?ai:\\é)".to_string(),false),
        ("(?ai:[é])".to_string(),false),
        ("(?a:\\w)\\w".to_string(),false),
        ("(?ai)\\141".to_string(),false),
        ("(?ai)[\\141]".to_string(),false),
        ("(?ai)[\\300-\\326]".to_string(),false),
        ("(a)\\1".to_string(),false),
        ("(a)\\18".to_string(),false),
        ("(a)\\118".to_string(),false),
        ("\\1(a)".to_string(),false),
        ("(a\\1)".to_string(),false),
        ("(?<=a(b)\\1)c".to_string(),false),
        ("(a)(?<=\\1)b".to_string(),false),
        ("\\0".to_string(),false),
        ("[\\0]".to_string(),false),
        ("(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\0".to_string(),false),
        ("\\00".to_string(),false),
        ("[\\00]".to_string(),false),
        ("(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\00".to_string(),false),
        ("\\000".to_string(),false),
        ("[\\000]".to_string(),false),
        ("(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\000".to_string(),false),
        ("\\0000".to_string(),false),
        ("[\\0000]".to_string(),false),
        ("(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\0000".to_string(),false),
        ("\\08".to_string(),false),
        ("[\\08]".to_string(),false),
        ("(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\08".to_string(),false),
        ("\\09".to_string(),false),
        ("[\\09]".to_string(),false),
        ("(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\09".to_string(),false),
        ("\\078".to_string(),false),
        ("[\\078]".to_string(),false),
        ("(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\078".to_string(),false),
        ("\\099".to_string(),false),
        ("[\\099]".to_string(),false),
        ("(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\099".to_string(),false),
        ("\\1".to_string(),false),
        ("[\\1]".to_string(),false),
        ("(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\1".to_string(),false),
        ("\\11".to_string(),false),
        ("[\\11]".to_string(),false),
        ("(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\11".to_string(),false),
        ("\\111".to_string(),false),
        ("[\\111]".to_string(),false),
        ("(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\111".to_string(),false),
        ("\\1111".to_string(),false),
        ("[\\1111]".to_string(),false),
        ("(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\1111".to_string(),false),
        ("\\118".to_string(),false),
        ("[\\118]".to_string(),false),
        ("(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\118".to_string(),false),
        ("\\141".to_string(),false),
        ("[\\141]".to_string(),false),
        ("(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\141".to_string(),false),
        ("\\1410".to_string(),false),
        ("[\\1410]".to_string(),false),
        ("(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\1410".to_string(),false),
        ("\\177".to_string(),false),
        ("[\\177]".to_string(),false),
        ("(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\177".to_string(),false),
        ("\\200".to_string(),false),
        ("[\\200]".to_string(),false),
        ("(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\200".to_string(),false),
        ("\\377".to_string(),false),
        ("[\\377]".to_string(),false),
        ("(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\377".to_string(),false),
        ("\\378".to_string(),false),
        ("[\\378]".to_string(),false),
        ("(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\378".to_string(),false),
        ("\\400".to_string(),false),
        ("[\\400]".to_string(),false),
        ("(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\400".to_string(),false),
        ("\\777".to_string(),false),
        ("[\\777]".to_string(),false),
        ("(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\777".to_string(),false),
        ("\\888".to_string(),false),
        ("[\\888]".to_string(),false),
        ("(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\888".to_string(),false),
        ("\\999".to_string(),false),
        ("[\\999]".to_string(),false),
        ("(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\999".to_string(),false),
        ("(?a)\\0".to_string(),false),
        ("(?a)[\\0]".to_string(),false),
        ("(?a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\0".to_string(),false),
        ("(?a)\\00".to_string(),false),
        ("(?a)[\\00]".to_string(),false),
        ("(?a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\00".to_string(),false),
        ("(?a)\\000".to_string(),false),
        ("(?a)[\\000]".to_string(),false),
        ("(?a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\000".to_string(),false),
        ("(?a)\\0000".to_string(),false),
        ("(?a)[\\0000]".to_string(),false),
        ("(?a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\0000".to_string(),false),
        ("(?a)\\08".to_string(),false),
        ("(?a)[\\08]".to_string(),false),
        ("(?a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\08".to_string(),false),
        ("(?a)\\09".to_string(),false),
        ("(?a)[\\09]".to_string(),false),
        ("(?a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\09".to_string(),false),
        ("(?a)\\078".to_string(),false),
        ("(?a)[\\078]".to_string(),false),
        ("(?a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\078".to_string(),false),
        ("(?a)\\099".to_string(),false),
        ("(?a)[\\099]".to_string(),false),
        ("(?a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\099".to_string(),false),
        ("(?a)\\1".to_string(),false),
        ("(?a)[\\1]".to_string(),false),
        ("(?a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\1".to_string(),false),
        ("(?a)\\11".to_string(),false),
        ("(?a)[\\11]".to_string(),false),
        ("(?a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\11".to_string(),false),
        ("(?a)\\111".to_string(),false),
        ("(?a)[\\111]".to_string(),false),
        ("(?a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\111".to_string(),false),
        ("(?a)\\1111".to_string(),false),
        ("(?a)[\\1111]".to_string(),false),
        ("(?a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\1111".to_string(),false),
        ("(?a)\\118".to_string(),false),
        ("(?a)[\\118]".to_string(),false),
        ("(?a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\118".to_string(),false),
        ("(?a)\\141".to_string(),false),
        ("(?a)[\\141]".to_string(),false),
        ("(?a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\141".to_string(),false),
        ("(?a)\\1410".to_string(),false),
        ("(?a)[\\1410]".to_string(),false),
        ("(?a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\1410".to_string(),false),
        ("(?a)\\177".to_string(),false),
        ("(?a)[\\177]".to_string(),false),
        ("(?a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\177".to_string(),false),
        ("(?a)\\200".to_string(),false),
        ("(?a)[\\200]".to_string(),false),
        ("(?a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\200".to_string(),false),
        ("(?a)\\377".to_string(),false),
        ("(?a)[\\377]".to_string(),false),
        ("(?a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\377".to_string(),false),
        ("(?a)\\378".to_string(),false),
        ("(?a)[\\378]".to_string(),false),
        ("(?a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\378".to_string(),false),
        ("(?a)\\400".to_string(),false),
        ("(?a)[\\400]".to_string(),false),
        ("(?a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\400".to_string(),false),
        ("(?a)\\777".to_string(),false),
        ("(?a)[\\777]".to_string(),false),
        ("(?a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\777".to_string(),false),
        ("(?a)\\888".to_string(),false),
        ("(?a)[\\888]".to_string(),false),
        ("(?a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\888".to_string(),false),
        ("(?a)\\999".to_string(),false),
        ("(?a)[\\999]".to_string(),false),
        ("(?a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\999".to_string(),false),
        ("(?ai)\\0".to_string(),false),
        ("(?ai)[\\0]".to_string(),false),
        ("(?ai)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\0".to_string(),false),
        ("(?ai)\\00".to_string(),false),
        ("(?ai)[\\00]".to_string(),false),
        ("(?ai)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\00".to_string(),false),
        ("(?ai)\\000".to_string(),false),
        ("(?ai)[\\000]".to_string(),false),
        ("(?ai)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\000".to_string(),false),
        ("(?ai)\\0000".to_string(),false),
        ("(?ai)[\\0000]".to_string(),false),
        ("(?ai)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\0000".to_string(),false),
        ("(?ai)\\08".to_string(),false),
        ("(?ai)[\\08]".to_string(),false),
        ("(?ai)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\08".to_string(),false),
        ("(?ai)\\09".to_string(),false),
        ("(?ai)[\\09]".to_string(),false),
        ("(?ai)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\09".to_string(),false),
        ("(?ai)\\078".to_string(),false),
        ("(?ai)[\\078]".to_string(),false),
        ("(?ai)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\078".to_string(),false),
        ("(?ai)\\099".to_string(),false),
        ("(?ai)[\\099]".to_string(),false),
        ("(?ai)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\099".to_string(),false),
        ("(?ai)\\1".to_string(),false),
        ("(?ai)[\\1]".to_string(),false),
        ("(?ai)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\1".to_string(),false),
        ("(?ai)\\11".to_string(),false),
        ("(?ai)[\\11]".to_string(),false),
        ("(?ai)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\11".to_string(),false),
        ("(?ai)\\111".to_string(),false),
        ("(?ai)[\\111]".to_string(),false),
        ("(?ai)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\111".to_string(),false),
        ("(?ai)\\1111".to_string(),false),
        ("(?ai)[\\1111]".to_string(),false),
        ("(?ai)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\1111".to_string(),false),
        ("(?ai)\\118".to_string(),false),
        ("(?ai)[\\118]".to_string(),false),
        ("(?ai)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\118".to_string(),false),
        ("(?ai)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\141".to_string(),false),
        ("(?ai)\\1410".to_string(),false),
        ("(?ai)[\\1410]".to_string(),false),
        ("(?ai)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\1410".to_string(),false),
        ("(?ai)\\177".to_string(),false),
        ("(?ai)[\\177]".to_string(),false),
        ("(?ai)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\177".to_string(),false),
        ("(?ai)\\200".to_string(),false),
        ("(?ai)[\\200]".to_string(),false),
        ("(?ai)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\200".to_string(),false),
        ("(?ai)\\377".to_string(),false),
        ("(?ai)[\\377]".to_string(),false),
        ("(?ai)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\377".to_string(),false),
        ("(?ai)\\378".to_string(),false),
        ("(?ai)[\\378]".to_string(),false),
        ("(?ai)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\378".to_string(),false),
        ("(?ai)\\400".to_string(),false),
        ("(?ai)[\\400]".to_string(),false),
        ("(?ai)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\400".to_string(),false),
        ("(?ai)\\777".to_string(),false),
        ("(?ai)[\\777]".to_string(),false),
        ("(?ai)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\777".to_string(),false),
        ("(?ai)\\888".to_string(),false),
        ("(?ai)[\\888]".to_string(),false),
        ("(?ai)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\888".to_string(),false),
        ("(?ai)\\999".to_string(),false),
        ("(?ai)[\\999]".to_string(),false),
        ("(?ai)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\999".to_string(),false),
        ("(?ai:(?u:(a))\\1)".to_string(),false),
        ("(ä)(?ai:\\1)(?i:\\1)".to_string(),false),
        ("(?ai:(a)\\1)(a)\\2".to_string(),false),
        ("(?A:a)".to_string(),false),
        ("(?a:(?A:a))".to_string(),false),
        ("\\(\\?A:a\\)".to_string(),false),
        ("[()?A:]".to_string(),false),
        ("(?ai:[()?A:])".to_string(),false),
        ("\\050\\077A:a\\051".to_string(),false),
        ("(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)(a)\\998".to_string(),false),
        ("(?ax)\u{85}".to_string(),false),
        ("(?aix)\u{85}".to_string(),false),
        ("(?x)\u{85}".to_string(),false),
]);
    let mut seen = std::collections::HashSet::new();
    patterns.retain(|case| seen.insert(case.clone()));
    patterns
}
fn ascii_octal_subjects() -> Vec<&'static str> {
    vec![
        "",
        "a",
        "A",
        "aa",
        "aA",
        "Aa",
        "AA",
        "b",
        "B",
        "k",
        "K",
        "K",
        "ſ",
        "s",
        "S",
        "i",
        "I",
        "İ",
        "ı",
        "é",
        "É",
        "ä",
        "Ä",
        "ää",
        "äÄ",
        "Ää",
        "ÄÄ",
        "ß",
        "ss",
        "α",
        "Α",
        "Ω",
        "ω",
        "0",
        "9",
        "١",
        "²",
        "Ⅸ",
        "_",
        "!",
        " ",
        "\t",
        "\n",
        "\r",
        "\u{b}",
        "\u{c}",
        "\u{1c}",
        "\u{1d}",
        "\u{1e}",
        "\u{1f}",
        "\u{85}",
        " ",
        " ",
        "\u{200b}",
        "　",
        "\0",
        "\08",
        "\t1",
        "a0",
        "a8",
        "I0",
        "ÿ",
        "Ā",
        "(",
        ")",
        "[",
        "]",
        "&",
        "~",
        "-",
        "\\",
        "\\141",
        "a\né",
        "aé",
        "éa",
        "é_",
        "_é",
        "abcABC",
        "aaaaaaaaaaaaaaaaaaaa",
        "aaaaaaaaaaaa8",
        "aaaaaaaaaaa8",
        "aaaaaaaaaaaaa8",
        "aaaaaaaaaaaaI",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8",
        "ääÄ",
        "äÄÄ",
        "(?A:a)",
    ]
}

#[test]
fn unicode_i_literals_classes_and_backreferences_keep_their_distinct_rules() {
    for (pattern, matched, clear) in [
        (r"(?i)^i$", vec!["i", "I", "İ", "ı"], vec!["j", "i\u{307}"]),
        (r"(?i)^[^i]$", vec!["j"], vec!["i", "I", "İ", "ı"]),
        (r"(?ai)^i$", vec!["i", "I"], vec!["İ", "ı"]),
        (r"(?ai:(?u:^ı$))", vec!["i", "I", "İ", "ı"], vec!["j"]),
        (
            r"(?i)^(.)\1$",
            vec!["iİ", "İi", "ıı", "Σσ", "Kk", "ßẞ"],
            vec!["iı", "σς", "µμ", "ſs", "ﬅﬆ"],
        ),
    ] {
        let scanner = make_scanner(json!([rule("fold", pattern, "body", "block")]));
        for (subjects, expected) in [(matched, Outcome::MatchBlocked), (clear, Outcome::NoMatch)] {
            for text in subjects {
                assert_eq!(
                    scanner
                        .scan_websocket_text(Direction::Request, MessageType::Text, text, block())
                        .unwrap()
                        .outcome,
                    expected,
                    "{pattern:?} {text:?}"
                );
            }
        }
    }
}

#[test]
fn ascii_backreferences_allow_ascii_changes_beside_identical_unicode_scalars() {
    let scanner = make_scanner(json!([rule("mixed", r"(?ai)^(.+)\1$", "body", "block")]));
    for (text, matched) in [
        ("äaäA", true),
        ("aİAİ", true),
        ("aıAı", true),
        ("µaµA", true),
        ("äaÄA", false),
        ("aİAI", false),
        ("µaμA", false),
    ] {
        assert_eq!(
            scanner
                .scan_websocket_text(
                    Direction::Response,
                    MessageType::Text,
                    text,
                    Options::default()
                )
                .unwrap()
                .finding
                .is_some(),
            matched,
            "{text:?}"
        );
    }
}

#[test]
#[ignore = "requires SAFEYOLO_POLICY_PYTHON with the shipped Python dependencies"]
fn python_unicode_literal_class_and_backreference_matrix() {
    let characters = [
        'I', 'i', 'İ', 'ı', 'j', 'J', 's', 'S', 'ſ', 'σ', 'ς', 'Σ', 'µ', 'μ', 'Μ', 'K', 'k', 'K',
        'Å', 'å', 'Å', 'ß', 'ẞ', 'α', 'Α', 'ä', 'Ä', 'ﬅ', 'ﬆ', 'é', 'É', '\u{307}', '\u{a7cb}',
        'ɤ',
    ];
    let mut subjects: Vec<String> = characters.iter().map(char::to_string).collect();
    for left in characters {
        for right in characters {
            subjects.push(format!("{left}{right}"));
            subjects.push(format!("{left}{right}X"));
        }
    }
    subjects.extend(
        [
            "", "i\u{307}", "aiaİ", "aİai", "KbKb", "KbKb", "σςσς", "σςσσ", "ſsſs", "ſssſ", "ıiıi",
            "ıiii", "äaäA", "aİAİ", "aıAı", "µaµA",
        ]
        .map(str::to_owned),
    );
    let mut patterns = vec![];
    for atom in [
        "i",
        "I",
        "İ",
        "ı",
        r"\x49",
        r"\u0130",
        r"[i]",
        r"[^i]",
        r"[İ]",
        r"[^İ]",
        r"[a-z]",
        r"[^a-z]",
        r"[I-J]",
        r"[\u012f-\u0131]",
        r"[^\u012f-\u0131]",
    ] {
        for (before, after) in [
            ("(?i:", ")"),
            ("(?ai:", ")"),
            ("(?ai:(?u:", "))"),
            ("(?i:(?-i:", "))"),
        ] {
            patterns.push(format!(r"\A{before}{atom}{after}\Z"));
        }
    }
    patterns.extend(
        [
            r"(?i)\A(.)\1\Z",
            r"(?ai)\A(.)\1\Z",
            r"\A(.)\1\Z",
            r"\A(.)(?i:\1)\Z",
            r"(?i)\A(.)(?-i:\1)\Z",
            r"(?i)\A(?P<a>.)(?P=a)\Z",
            r"(?i)\A(.+)\1\Z",
            r"(?ai)\A(.+)\1\Z",
            r"(?i)\A(.)(?a:\1)\Z",
            r"(?ai)\A(.)(?u:\1)\Z",
            r"(?i)\A((?:.{2}))\1\Z",
            r"(?i)\A(.)\1(?-i:X)\Z",
            r"(?i)\A(σ)\1\Z",
            r"(?i)\A(ſ)\1\Z",
            r"(?i)\A(ı)\1\Z",
            r"(?i)\A(İ)\1\Z",
            r"(?i)\A(µ)\1\Z",
            r"(?i)\A(K)\1\Z",
            r"(?i)\A(ß)\1\Z",
            r"(?i)\A(.)\1(?<=\1)\Z",
        ]
        .map(str::to_owned),
    );
    let input = json!({"patterns":patterns,"texts":subjects});
    let old = python(
        r#"
import json,sys
from safeyolo.detection.patterns import compile_pattern
source=json.load(sys.stdin)
results=[]
for expression in source['patterns']:
    compiled=compile_pattern(expression)
    assert compiled is not None
    results.append([bool(compiled.search(text)) for text in source['texts']])
print(json.dumps(results))
"#,
        &input,
    );
    for (pattern, expected) in patterns.iter().zip(old.as_array().unwrap()) {
        let scanner = make_scanner(json!([rule("matrix", pattern, "body", "log")]));
        for (text, matched) in subjects.iter().zip(expected.as_array().unwrap()) {
            let actual = scanner
                .scan_websocket_text(
                    Direction::Request,
                    MessageType::Text,
                    text,
                    Options::default(),
                )
                .unwrap()
                .finding
                .is_some();
            assert_eq!(json!(actual), *matched, "{pattern:?} {text:?}");
        }
    }
    eprintln!(
        "Compared {} Python Unicode patterns x {} subjects = {} matches",
        patterns.len(),
        subjects.len(),
        patterns.len() * subjects.len()
    );
}
