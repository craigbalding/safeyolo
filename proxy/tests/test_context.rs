use safeyolo_proxy::test_context::{
    Context, ContextSource, HEADER, Options, Reason, Request, RequestOutcome, TestContext,
    TrustedIdentity, api_current, capture_body,
};
use serde_json::{Value, json};
use std::sync::{Arc, Barrier};

fn context(value: &str) -> Context {
    Context::parse(value).unwrap()
}
fn identity(source: &str, agent: &str) -> TrustedIdentity {
    TrustedIdentity::new(source, agent).unwrap()
}
fn configured(block: bool, inject: bool, ttl: Value) -> TestContext {
    let owner = TestContext::default();
    owner.configure(Some(&json!({"policy_hash":"test", "addons":{"test_context":{
        "target_hosts":["*.target.invalid"], "inject_declared":inject, "declared_ttl_max":ttl
    }}})), Options { block, ..Options::default() }).unwrap();
    owner
}
fn request(
    owner: &TestContext,
    host: &str,
    header: Option<&str>,
    who: Option<&TrustedIdentity>,
    now: f64,
) -> RequestOutcome {
    let mut headers = vec![("X-Test-Context".into(), b"legacy-unchanged".to_vec())];
    if let Some(value) = header {
        headers.push((HEADER.into(), value.as_bytes().to_vec()));
    }
    let outcome = owner
        .request(
            Request {
                host,
                prior_response: false,
                identity: who,
                metadata_agent: who.map(TrustedIdentity::agent),
            },
            &mut headers,
            now,
        )
        .unwrap();
    assert_eq!(
        headers,
        [("X-Test-Context".into(), b"legacy-unchanged".to_vec())]
    );
    outcome
}

#[test]
fn canonical_parser_rejects_ambiguous_or_unsafe_fields_and_preserves_extra_case() {
    let parsed = context(
        " ;z=Z;agent=alice;step=2;run=R-1;A=upper;expect=blocked;role=probe;test=T:1;intent=read;suite=S;subject=one; ",
    );
    assert_eq!(
        parsed.format(),
        "run=R-1;agent=alice;role=probe;suite=S;subject=one;step=2;test=T:1;intent=read;expect=blocked;A=upper;z=Z"
    );
    assert_eq!(
        parsed.header_line(),
        format!("{HEADER}: {}", parsed.format())
    );
    assert_eq!(
        context("\u{001c}\u{2003}run = R ; agent=alice\u{001f}").format(),
        "run=R;agent=alice"
    );
    for input in [
        "",
        " ; ; ",
        "Run=r;agent=a",
        "run=r;agent=a;run=r",
        "run=r;agent=a;b=x=y",
        "run=r;agent=a;x=y z",
        "run=r;agent=a;x=é",
        "run=r;agent=a;x=\0",
        "run=r;agent=a;x=y\nz",
    ] {
        assert!(Context::parse(input).is_err(), "{input:?}");
    }
    let twenty = format!(
        "run=r;agent=a;{}",
        (0..18)
            .map(|index| format!("extra{index}=x"))
            .collect::<Vec<_>>()
            .join(";")
    );
    assert_eq!(context(&twenty).fields().len(), 20);
    assert!(Context::parse(&format!("{twenty};extra18=x")).is_err());
    assert!(
        Context::from_pairs(vec![
            ("run".into(), "r".into()),
            ("agent".into(), "a".into()),
            ("run".into(), "r".into())
        ])
        .is_err()
    );
}

#[test]
fn declarations_cap_exact_integer_ttls_expire_at_boundary_and_remain_source_scoped() {
    let owner = configured(true, true, json!(10));
    let alice = identity("uds:alice", "alice");
    let bob = identity("uds:bob", "bob");
    let declared = context("run=R;agent=claimed");
    assert_eq!(
        owner
            .set_declaration(&alice, declared.clone(), Some(&json!(100)), 100.25)
            .unwrap(),
        serde_json::Number::from(10)
    );
    assert_eq!(
        owner
            .get_declaration(&alice, 109.3)
            .unwrap()
            .unwrap()
            .expires_in,
        serde_json::Number::from(1)
    );
    assert!(owner.get_declaration(&bob, 100.25).unwrap().is_none());
    assert!(owner.get_declaration(&alice, 110.25).unwrap().is_none());
    assert_eq!(owner.stats(110.25).unwrap().declared_active, 0);
    for invalid in [
        json!(true),
        json!(false),
        json!(0),
        json!(-1),
        json!(1.0),
        json!("1"),
        json!([]),
    ] {
        assert!(
            owner
                .set_declaration(&alice, declared.clone(), Some(&invalid), 0.)
                .is_err()
        );
    }
    let huge: Value = serde_json::from_str("18446744073709551617").unwrap();
    assert_eq!(
        owner
            .set_declaration(&alice, declared.clone(), Some(&huge), 0.)
            .unwrap(),
        serde_json::Number::from(10)
    );
    let large_owner = configured(true, true, huge.clone());
    assert_eq!(
        large_owner
            .set_declaration(&alice, declared.clone(), None, 0.)
            .unwrap(),
        huge.as_number().unwrap().clone()
    );
    assert!(large_owner.get_declaration(&alice, 1.).unwrap().is_some());
    let extreme_owner = configured(true, true, json!(1));
    extreme_owner
        .set_declaration(&alice, declared.clone(), None, f64::MAX)
        .unwrap();
    assert!(extreme_owner.get_declaration(&alice, -f64::MAX).is_err());
    let enormous: Value = serde_json::from_str(&format!("1{}", "0".repeat(400))).unwrap();
    large_owner.configure(Some(&json!({"policy_hash":"large", "addons":{"test_context":{"declared_ttl_max":enormous}}})), Options::default()).unwrap();
    assert!(
        large_owner
            .set_declaration(&alice, declared.clone(), None, 0.)
            .is_err()
    );
    assert!(large_owner.get_declaration(&alice, 1.).unwrap().is_some());
    assert!(
        owner
            .set_declaration(&alice, declared, None, f64::NAN)
            .is_err()
    );
    for (source, agent) in [
        ("", "alice"),
        ("unknown", "alice"),
        ("uds:a", ""),
        ("uds:a", "default"),
        ("uds:a", "unknown"),
    ] {
        assert!(TrustedIdentity::new(source, agent).is_err());
    }
}

#[test]
fn source_reuse_invalidates_old_agent_and_delete_clears_reused_source_slot() {
    let owner = configured(true, true, json!(900));
    let alice = identity("slot:1", "alice");
    let bob = identity("slot:1", "bob");
    owner
        .set_declaration(&alice, context("run=old;agent=alice"), None, 0.)
        .unwrap();
    assert!(owner.get_declaration(&bob, 1.).unwrap().is_none());
    assert!(owner.get_declaration(&alice, 1.).unwrap().is_none());
    owner
        .set_declaration(&alice, context("run=old;agent=alice"), None, 0.)
        .unwrap();
    assert!(owner.clear_declaration(&bob).unwrap());
    assert!(!owner.clear_declaration(&bob).unwrap());
    owner
        .set_declaration(&bob, context("run=new;agent=bob"), None, 1.)
        .unwrap();
    assert_eq!(
        owner
            .get_declaration(&bob, 2.)
            .unwrap()
            .unwrap()
            .context
            .get("run"),
        Some("new")
    );
    assert!(
        TestContext::default()
            .get_declaration(&bob, 2.)
            .unwrap()
            .is_none()
    );
}

#[test]
fn shared_declarations_never_lose_a_concurrent_replacement_to_expiry_cleanup() {
    for _ in 0..40 {
        let owner = configured(true, true, json!(100));
        let alice = identity("slot:a", "alice");
        owner
            .set_declaration(&alice, context("run=old;agent=alice"), Some(&json!(1)), 0.)
            .unwrap();
        let barrier = Arc::new(Barrier::new(3));
        std::thread::scope(|scope| {
            let barrier_reader = barrier.clone();
            let owner_reader = owner.clone();
            let alice_reader = alice.clone();
            scope.spawn(move || {
                barrier_reader.wait();
                owner_reader.get_declaration(&alice_reader, 2.).unwrap();
            });
            let barrier_writer = barrier.clone();
            let owner_writer = owner.clone();
            let alice_writer = alice.clone();
            scope.spawn(move || {
                barrier_writer.wait();
                owner_writer
                    .set_declaration(
                        &alice_writer,
                        context("run=new;agent=alice"),
                        Some(&json!(10)),
                        2.,
                    )
                    .unwrap();
            });
            barrier.wait();
        });
        assert_eq!(
            owner
                .get_declaration(&alice, 2.)
                .unwrap()
                .unwrap()
                .context
                .get("run"),
            Some("new")
        );
    }
    let owner = configured(true, true, json!(100));
    std::thread::scope(|scope| {
        for index in 0..24 {
            let owner = owner.clone();
            scope.spawn(move || {
                let who = identity(&format!("slot:{index}"), &format!("agent{index}"));
                owner
                    .set_declaration(
                        &who,
                        context(&format!("run=R;agent=agent{index}")),
                        None,
                        0.,
                    )
                    .unwrap();
                assert_eq!(
                    owner
                        .get_declaration(&who, 1.)
                        .unwrap()
                        .unwrap()
                        .context
                        .get("agent"),
                    Some(who.agent())
                );
            });
        }
    });
    assert_eq!(owner.stats(1.).unwrap().declared_active, 24);
    assert_eq!(owner.stats(100.).unwrap().declared_active, 0);
}

#[test]
fn valid_header_wins_malformed_nonempty_never_inherits_and_trusted_agent_stays_distinct() {
    let owner = configured(true, true, json!(10));
    let alice = identity("uds:alice", "alice");
    owner
        .set_declaration(&alice, context("run=declared;agent=alice"), None, 0.)
        .unwrap();
    let RequestOutcome::Applied { applied } = request(
        &owner,
        "TARGET.INVALID",
        Some("run=explicit;agent=mallory;role=probe;custom=yes"),
        Some(&alice),
        1.,
    ) else {
        panic!()
    };
    assert_eq!(applied.source, ContextSource::Header);
    assert_eq!(applied.trusted_agent.as_deref(), Some("alice"));
    assert_eq!(applied.test_agent_match, Some(false));
    assert!(!applied.live_metadata.contains_key("agent"));
    assert!(!applied.live_metadata.contains_key("custom"));
    assert_eq!(applied.live_metadata["test_context"]["custom"], "yes");
    assert_eq!(applied.live_metadata["test_role"], "probe");
    for header in [None, Some("")] {
        let RequestOutcome::Applied { applied } =
            request(&owner, "deep.target.invalid", header, Some(&alice), 1.)
        else {
            panic!()
        };
        assert_eq!(applied.source, ContextSource::Declared);
        assert_eq!(applied.context.get("run"), Some("declared"));
    }
    for malformed in [" ", "\t", "run=broken", "run=x;agent=a;run=z"] {
        assert!(matches!(
            request(&owner, "target.invalid", Some(malformed), Some(&alice), 1.),
            RequestOutcome::Block {
                reason: Reason::MalformedContext,
                status: 428,
                ..
            }
        ));
    }
    assert!(matches!(
        request(&owner, "target.invalid", None, None, 1.),
        RequestOutcome::Block {
            reason: Reason::MissingContext,
            ..
        }
    ));
    assert!(matches!(
        request(&owner, "target.invalid", None, Some(&alice), 10.),
        RequestOutcome::Block {
            reason: Reason::MissingContext,
            ..
        }
    ));
}

#[test]
fn host_targets_optional_headers_duplicates_and_prior_response_preserve_shipped_modes() {
    let owner = configured(false, true, json!(10));
    for host in ["target.invalid.evil", "not-target.invalid", "else.invalid"] {
        assert_eq!(
            request(&owner, host, None, None, 0.),
            RequestOutcome::NotTargetHost
        );
        assert_eq!(
            request(&owner, host, Some("broken"), None, 0.),
            RequestOutcome::Warn {
                reason: Reason::MalformedOptionalContext,
                resolved_agent: None
            }
        );
        assert!(
            matches!(request(&owner, host, Some("run=r;agent=untrusted"), None, 0.), RequestOutcome::Applied { applied } if applied.test_agent_match.is_none())
        );
    }
    assert_eq!(
        request(&owner, "target.invalid", None, None, 0.),
        RequestOutcome::Warn {
            reason: Reason::MissingContext,
            resolved_agent: None
        }
    );
    let mut headers = vec![
        (HEADER.into(), b"run=r;agent=a".to_vec()),
        (HEADER.to_lowercase(), b"run=r;agent=a".to_vec()),
    ];
    let invoke = Request {
        host: "target.invalid",
        prior_response: false,
        identity: None,
        metadata_agent: None,
    };
    assert_eq!(
        owner.request(invoke, &mut headers, 0.).unwrap(),
        RequestOutcome::Warn {
            reason: Reason::MalformedContext,
            resolved_agent: None
        }
    );
    assert!(headers.is_empty());
    let mut headers = vec![(HEADER.into(), vec![0xff])];
    assert_eq!(
        owner
            .request(
                Request {
                    host: "target.invalid",
                    prior_response: false,
                    identity: None,
                    metadata_agent: None
                },
                &mut headers,
                0.
            )
            .unwrap(),
        RequestOutcome::Warn {
            reason: Reason::MalformedContext,
            resolved_agent: None
        }
    );
    assert!(headers.is_empty());
    let before = owner.stats(0.).unwrap();
    let mut headers = vec![(HEADER.into(), b"broken".to_vec())];
    assert_eq!(
        owner
            .request(
                Request {
                    host: "target.invalid",
                    prior_response: true,
                    identity: None,
                    metadata_agent: None
                },
                &mut headers,
                f64::NAN
            )
            .unwrap(),
        RequestOutcome::PriorResponse
    );
    assert_eq!(headers.len(), 1);
    assert_eq!(owner.stats(0.).unwrap(), before);
    let owner = TestContext::default();
    owner.configure(Some(&json!({"policy_hash":"literal", "addons":{"test_context":{"target_hosts":["*", "api?.invalid"]}}})), Options::default()).unwrap();
    assert_eq!(
        request(&owner, "api1.invalid", None, None, 0.),
        RequestOutcome::NotTargetHost
    );
}

#[test]
fn configuration_hash_controls_targets_but_not_dynamic_declaration_options_or_existing_expiry() {
    let owner = TestContext::default();
    let who = identity("slot:a", "alice");
    owner
        .configure(
            Some(&json!({"addons":{"test_context":{"target_hosts":["target.invalid"]}}})),
            Options::default(),
        )
        .unwrap();
    assert!(!owner.stats(0.).unwrap().active); // Initial empty hash does not trigger target reload.
    owner.configure(Some(&json!({"policy_hash":"one", "addons":{"test_context":{"target_hosts":["target.invalid"],"inject_declared":true,"declared_ttl_max":20}}})), Options::default()).unwrap();
    owner
        .set_declaration(&who, context("run=r;agent=alice"), None, 0.)
        .unwrap();
    owner.configure(Some(&json!({"policy_hash":"one", "addons":{"test_context":{"target_hosts":[],"inject_declared":false,"declared_ttl_max":2}}})), Options::default()).unwrap();
    assert!(owner.stats(0.).unwrap().active);
    assert_eq!(
        owner.get_declaration(&who, 1.).unwrap().unwrap().expires_in,
        serde_json::Number::from(19)
    );
    assert!(matches!(
        request(&owner, "target.invalid", None, Some(&who), 1.),
        RequestOutcome::Block { .. }
    ));
    owner.configure(Some(&json!({"policy_hash":"two", "addons":{"test_context":{"target_hosts":["target.invalid"],"inject_declared":"wrong","declared_ttl_max":true}}})), Options {block:false, inject_declared:true, declared_ttl:json!(7)}).unwrap();
    assert!(matches!(
        request(&owner, "target.invalid", None, Some(&who), 1.),
        RequestOutcome::Applied { .. }
    ));
    assert_eq!(
        owner
            .set_declaration(&who, context("run=r;agent=a"), None, 2.)
            .unwrap(),
        serde_json::Number::from(7)
    );
    owner
        .configure(
            None,
            Options {
                declared_ttl: json!("wrong"),
                ..Options::default()
            },
        )
        .unwrap();
    assert!(owner.stats(2.).unwrap().active);
    assert_eq!(
        owner
            .set_declaration(&who, context("run=r;agent=a"), None, 2.)
            .unwrap(),
        serde_json::Number::from(900)
    );
    assert!(owner.configure(Some(&json!({"policy_hash":"bad", "addons":{"test_context":{"target_hosts":[false]}}})), Options::default()).is_err());
    assert!(owner.stats(2.).unwrap().active);
}

#[test]
fn api_uses_only_authenticated_source_identity_and_preserves_mutation_responses() {
    let owner = TestContext::default();
    let call = |source, agent, method, body: Option<&Value>, now| {
        api_current(Some(&owner), source, agent, method, body, now).unwrap()
    };
    assert_eq!(call(None, None, "PUT", None, 0.).status, 403);
    assert_eq!(
        call(None, Some("alice"), "GET", None, 0.).body["error"],
        "Could not identify source"
    );
    assert_eq!(
        api_current(None, Some("s:a"), Some("alice"), "GET", None, 0.)
            .unwrap()
            .status,
        503
    );
    let spoof = json!({"context":"run=R;agent=bob", "ttl":10, "agent":"bob", "source_id":"s:b"});
    let posted = call(Some("s:a"), Some("alice"), "POST", Some(&spoof), 1.);
    assert_eq!(
        posted.body,
        json!({"status":"set","agent":"alice","expires_in":10,"context":{"run":"R","agent":"bob"}})
    );
    assert_eq!(posted.audit.unwrap().details["test_agent_match"], false);
    assert_eq!(
        call(Some("s:b"), Some("bob"), "GET", None, 2.).body,
        json!({"agent":"bob","context":null})
    );
    assert_eq!(
        call(Some("s:a"), Some("alice"), "GET", None, 2.).body["expires_in"],
        9
    );
    for body in [json!(null), json!([]), json!("not-an-object")] {
        assert_eq!(
            call(Some("s:a"), Some("alice"), "POST", Some(&body), 2.).status,
            400
        );
    }
    for ttl in [json!(true), json!(0), json!(-1), json!(1.0), json!("1")] {
        assert_eq!(
            call(
                Some("s:a"),
                Some("alice"),
                "POST",
                Some(&json!({"context":"run=R;agent=alice", "ttl":ttl})),
                2.
            )
            .body["error"],
            "ttl must be a positive integer (seconds)"
        );
    }
    assert_eq!(
        call(Some("s:a"), Some("alice"), "PATCH", None, 2.).status,
        405
    );
    assert_eq!(
        call(Some("s:a"), Some("alice"), "DELETE", None, 2.)
            .audit
            .unwrap()
            .details["had_declaration"],
        true
    );
    assert_eq!(
        call(Some("s:a"), Some("alice"), "DELETE", None, 2.)
            .audit
            .unwrap()
            .details["had_declaration"],
        false
    );
    assert_eq!(
        call(Some("s:a"), Some("alice"), "GET", None, 2.).body["context"],
        Value::Null
    );
}

#[test]
fn body_capture_preserves_byte_head_lossy_decode_and_tail_rules() {
    assert_eq!(capture_body(&[], 4, 5), "");
    assert_eq!(
        capture_body("éx".as_bytes(), 1, 5),
        "�\n...[truncated, 3 bytes total]...\n"
    );
    assert_eq!(
        capture_body(b"one\ntwo\nthree\n", 3, 2),
        "one\n...[truncated, 14 bytes total]...\ntwo\nthree"
    );
    assert_eq!(
        capture_body(b"one\ntwo\n", 3, 2),
        "one\n...[truncated, 8 bytes total]...\n"
    );
    assert_eq!(
        capture_body(b"one\ntwo\n", 0, 0),
        "\n...[truncated, 8 bytes total]...\none\ntwo"
    );
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

#[test]
#[ignore = "Actual Python parser/formatter and body-capture oracle; set SAFEYOLO_POLICY_PYTHON"]
fn python_parser_formatter_and_body_capture_differential() {
    let mut inputs: Vec<String> = [
        "",
        " ",
        ";;",
        "agent=a",
        "run=r",
        "run=r;agent=a",
        "run=r;agent=a;run=z",
        "run=r;agent=a;X=x;x=X",
        "agent=a;z=z;run=r;test=t;A=a",
        "run=r;agent=a;key=",
        "run=r;agent=a;=value",
        "run=r;agent=a;x=y=z",
        "run=r;agent=a;missing",
        "run=r;agent=a;quote'",
        "run=r;agent=a;quote\"",
        "run=r;agent=a;quote'\"",
        "run=r;agent=a;é=x",
        "run=r;agent=a;zero\0=x",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    for ch in [
        '\u{1c}', '\u{1d}', '\u{1e}', '\u{1f}', '\u{85}', '\u{a0}', '\u{2003}', '\u{200b}',
        '\u{2028}', '\u{feff}',
    ] {
        inputs.push(format!("{ch}run=r;agent=a{ch}"));
        inputs.push(format!("run=r;agent=a;bad{ch}key=x"));
    }
    for count in [18, 19] {
        inputs.push(format!(
            "run=r;agent=a;{}",
            (0..count)
                .map(|index| format!("x{index}=v"))
                .collect::<Vec<_>>()
                .join(";")
        ));
    }
    let expected: Vec<_> = inputs
        .iter()
        .map(|input| match Context::parse(input) {
            Ok(context) => {
                json!({"fields":context, "format":context.format(),"header":context.header_line()})
            }
            Err(error) => json!({"error":error.to_string()}),
        })
        .collect();
    let actual = python(
        r#"
import json,sys
from safeyolo.test_context_contract import parse_test_context,format_test_context,format_test_context_header,TestContextError
out=[]
for value in json.load(sys.stdin):
    try:
        context=parse_test_context(value)
        out.append(dict(fields=context,format=format_test_context(context),header=format_test_context_header(context)))
    except TestContextError as error: out.append(dict(error=str(error)))
print(json.dumps(out))
"#,
        &json!(inputs),
    );
    for ((input, actual), expected) in inputs.iter().zip(actual.as_array().unwrap()).zip(expected) {
        assert_eq!(*actual, expected, "input {input:?}");
    }
    let bodies = [
        b"".to_vec(),
        b"one\ntwo\nthree\n".to_vec(),
        "éx\nnext".as_bytes().to_vec(),
        vec![0xff, 0xc0, 0x80, 0xed, 0xa0, 0x80],
        vec![b'x'; 17000],
    ];
    let mut cases = Vec::new();
    let mut expected = Vec::new();
    for body in bodies {
        for (head, tail) in [(0, 0), (1, 0), (1, 2), (4096, 5)] {
            cases.push(json!({"body":body,"head":head,"tail":tail}));
            expected.push(capture_body(&body, head, tail));
        }
    }
    assert_eq!(
        python(
            r#"
import json,sys
from safeyolo.mitm_addons.test_context import _capture_body
print(json.dumps([_capture_body(bytes(c['body']),c['head'],c['tail']) for c in json.load(sys.stdin)]))
"#,
            &json!(cases)
        ),
        json!(expected)
    );
    eprintln!(
        "Compared {} actual Python parser cases and {} body-capture cases",
        inputs.len(),
        cases.len()
    );
}

fn native_request_case(case: &Value) -> Value {
    let owner = configured(
        case["block"].as_bool().unwrap(),
        case["inject"].as_bool().unwrap(),
        json!(10),
    );
    owner
        .set_declaration(
            &identity("slot:a", "alice"),
            context("run=declared;agent=alice;test=T"),
            None,
            0.,
        )
        .unwrap();
    let who = case["agent"]
        .as_str()
        .map(|agent| identity(case["source"].as_str().unwrap(), agent));
    let mut headers = vec![("X-Test-Context".into(), b"legacy".to_vec())];
    for (index, value) in case["headers"].as_array().unwrap().iter().enumerate() {
        let bytes = value
            .as_str()
            .map(|v| v.as_bytes().to_vec())
            .unwrap_or_else(|| {
                value
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|n| n.as_u64().unwrap() as u8)
                    .collect()
            });
        headers.push((
            if index == 0 {
                HEADER.into()
            } else {
                HEADER.to_lowercase()
            },
            bytes,
        ));
    }
    let now = case["now"].as_f64().unwrap();
    let prior = case["prior"].as_bool().unwrap();
    let outcome = owner
        .request(
            Request {
                host: case["host"].as_str().unwrap(),
                prior_response: prior,
                identity: who.as_ref(),
                metadata_agent: case["metadata_agent"].as_str(),
            },
            &mut headers,
            now,
        )
        .unwrap();
    let mut metadata = serde_json::Map::new();
    if let Some(agent) = case["metadata_agent"].as_str() {
        metadata.insert("agent".into(), json!(agent));
    }
    let (status, body) = if let RequestOutcome::Block { status, body, .. } = &outcome {
        (*status, body.clone())
    } else if prior {
        (200, Value::Null)
    } else {
        (0, Value::Null)
    };
    if let RequestOutcome::Applied { applied } = &outcome {
        metadata.extend(applied.live_metadata.clone());
    }
    if let Some(agent) = outcome.trusted_identity_update() {
        metadata.insert("agent".into(), json!(agent));
    }
    json!({"metadata":metadata,"status":status,"body":body,"headers":headers,"stats":owner.stats(now).unwrap()})
}

#[test]
#[ignore = "Actual Python TestContext request matrix; set SAFEYOLO_POLICY_PYTHON"]
fn python_request_decisions_metadata_header_removal_and_stats_differential() {
    let mut cases = Vec::new();
    for host in ["target.invalid", "DEEP.TARGET.INVALID", "other.invalid"] {
        for headers in [
            json!([]),
            json!([""]),
            json!([" "]),
            json!(["broken"]),
            json!(["run=explicit;agent=alice;role=probe;x=y"]),
            json!(["run=explicit;agent=claimed"]),
            json!(["run=r;agent=a", "run=r;agent=a"]),
            json!([[255]]),
        ] {
            for block in [true, false] {
                for inject in [true, false] {
                    for agent in [Some("alice"), None] {
                        cases.push(json!({"host":host,"headers":headers,"block":block,"inject":inject,"agent":agent,"metadata_agent":agent,"source":"slot:a","prior":false,"now":1}));
                    }
                }
            }
        }
    }
    for (agent, source, now, metadata_agent, prior) in [
        (Some("bob"), "slot:a", 1, Some("alice"), false),
        (Some("alice"), "slot:b", 1, None, false),
        (Some("alice"), "slot:a", 10, None, false),
        (Some("alice"), "slot:a", 1, None, true),
    ] {
        for headers in [
            json!([]),
            json!([""]),
            json!(["broken"]),
            json!(["run=R;agent=claimed"]),
        ] {
            cases.push(json!({"host":"target.invalid","headers":headers,"block":true,"inject":true,"agent":agent,"metadata_agent":metadata_agent,"source":source,"prior":prior,"now":now}));
        }
    }
    let actual = python(
        r#"
import json,sys
from mitmproxy import http
from mitmproxy.test import tflow
import safeyolo.mitm_addons.test_context as module
module.write_event=lambda *args,**kwargs:None
out=[]
for case in json.load(sys.stdin):
    owner=module.TestContext()
    owner._target_hosts=['*.target.invalid']
    owner._maybe_reload_config=lambda:None
    owner._declared_ttl_max=lambda:10
    owner._inject_declared_enabled=lambda:case['inject']
    owner.should_block=lambda:case['block']
    owner.log_decision=lambda *args,**kwargs:None
    module.time.monotonic=lambda:0
    owner.set_declaration('slot:a','alice',dict(run='declared',agent='alice',test='T'),None)
    module.time.monotonic=lambda:case['now']
    module.get_client_ip=lambda flow:case['source']
    def resolve(flow):
        if case['agent'] is not None: flow.metadata['agent']=case['agent']
        return case['agent']
    owner._trusted_agent=resolve
    flow=tflow.tflow()
    flow.request.host=case['host']
    pairs=[(b'X-Test-Context',b'legacy')]
    for index,value in enumerate(case['headers']):
        pairs.append(((module.TEST_CONTEXT_HEADER if index==0 else module.TEST_CONTEXT_HEADER.lower()).encode(),value.encode() if isinstance(value,str) else bytes(value)))
    flow.request.headers=http.Headers(pairs)
    flow.metadata={}
    if case['metadata_agent'] is not None:flow.metadata['agent']=case['metadata_agent']
    flow.response=http.Response.make(200,b'') if case['prior'] else None
    owner.request(flow)
    metadata={k:v for k,v in flow.metadata.items() if k=='agent' or k.startswith('test_')}
    out.append(dict(metadata=metadata,status=flow.response.status_code if flow.response else 0,
        body=json.loads(flow.response.content) if flow.response and not case['prior'] else None,
        headers=[[key.decode(),list(value)] for key,value in flow.request.headers.fields],stats=owner.get_stats()))
print(json.dumps(out))
"#,
        &json!(cases),
    );
    for (case, actual) in cases.iter().zip(actual.as_array().unwrap()) {
        assert_eq!(native_request_case(case), *actual, "{case}");
    }
    eprintln!(
        "Compared {} actual Python request decisions, metadata, headers and counters",
        cases.len()
    );
}

#[test]
#[ignore = "Actual Python Agent API declaration operations and config fallback; set SAFEYOLO_POLICY_PYTHON"]
fn python_declaration_api_and_dynamic_configuration_differential() {
    let mut operations = vec![
        json!({"method":"GET","source":"slot:a","agent":"alice","body":null,"now":0}),
        json!({"method":"POST","source":"slot:a","agent":"alice","body":{"context":"run=R;agent=bob","ttl":100,"agent":"bob","source_id":"slot:b"},"now":0}),
        json!({"method":"GET","source":"slot:b","agent":"bob","body":null,"now":1}),
        json!({"method":"GET","source":"slot:a","agent":"alice","body":null,"now":0.1}),
        json!({"method":"GET","source":"slot:a","agent":"alice","body":null,"now":9.1}),
        json!({"method":"GET","source":"slot:a","agent":"alice","body":null,"now":10}),
    ];
    for body in [
        json!(null),
        json!([]),
        json!("x"),
        json!({}),
        json!({"context":10}),
        json!({"context":"run="}),
        json!({"context":"run=R;agent=a;bad'key="}),
    ] {
        operations
            .push(json!({"method":"POST","source":"slot:a","agent":"alice","body":body,"now":11}));
    }
    for ttl in [
        json!(true),
        json!(false),
        json!(-1),
        json!(0),
        json!(1.0),
        json!("5"),
        json!(null),
        json!(3),
    ] {
        operations.push(json!({"method":"POST","source":"slot:a","agent":"alice","body":{"context":"run=R;agent=declared","ttl":ttl},"now":12}));
    }
    for (method, source, agent, available) in [
        ("POST", Some("slot:b"), Some("bob"), true),
        ("GET", Some("slot:a"), Some("bob"), true),
        ("GET", Some("slot:a"), Some("alice"), true),
        ("GET", Some("slot:b"), Some("bob"), true),
        ("DELETE", Some("slot:b"), Some("bob"), true),
        ("DELETE", Some("slot:b"), Some("bob"), true),
        ("PATCH", Some("slot:a"), Some("alice"), true),
        ("GET", None, Some("alice"), true),
        ("GET", Some("slot:a"), None, true),
        ("GET", Some("slot:a"), Some("alice"), false),
    ] {
        operations.push(json!({"method":method,"source":source,"agent":agent,"available":available,"body":{"context":"run=R;agent=bob"},"now":13}));
    }
    let owner = configured(true, false, json!(10));
    let expected: Vec<_> = operations
        .iter()
        .map(|operation| {
            api_current(
                if operation["available"] == false {
                    None
                } else {
                    Some(&owner)
                },
                operation["source"].as_str(),
                operation["agent"].as_str(),
                operation["method"].as_str().unwrap(),
                Some(&operation["body"]),
                operation["now"].as_f64().unwrap(),
            )
            .unwrap()
        })
        .collect();
    let actual = python(
        r#"
import json,sys
from mitmproxy.test import tflow
import safeyolo.mitm_addons.test_context as tc_module
import safeyolo.mitm_addons.agent_api as api_module
import safeyolo.core.utils as utils
owner=tc_module.TestContext()
owner._declared_ttl_max=lambda:10
api=api_module.AgentAPI()
out=[]
for operation in json.load(sys.stdin):
    tc_module.time.monotonic=lambda:operation['now']
    result={}
    def respond(flow,status,body):result.update(status=status,body=body)
    def event(name,**kwargs):result['audit']=dict(event=name,source_id=operation['source'],trusted_agent=operation['agent'],details=kwargs['details'])
    api._respond=respond
    api_module.write_event=event
    api._resolve_agent_id=lambda flow:operation['agent']
    utils.get_client_ip=lambda flow:operation['source']
    api._find_addon=lambda name:owner if operation.get('available',True) else None
    api._read_json_body=lambda flow:operation['body']
    flow=tflow.tflow()
    flow.request.method=operation['method']
    api._handle_test_context_current(flow)
    result.setdefault('audit',None)
    out.append(result)
print(json.dumps(out))
"#,
        &json!(operations),
    );
    for ((operation, expected), actual) in operations
        .iter()
        .zip(expected)
        .zip(actual.as_array().unwrap())
    {
        assert_eq!(json!(expected), *actual, "{operation}");
    }
    let configs = vec![
        json!({}),
        json!({"policy_hash":"a","addons":{"test_context":{"target_hosts":["target.invalid"],"inject_declared":true,"declared_ttl_max":7}}}),
        json!({"policy_hash":"a","addons":{"test_context":{"target_hosts":[],"inject_declared":false,"declared_ttl_max":2}}}),
        json!({"policy_hash":"b","addons":{"test_context":{"target_hosts":["*.target.invalid"],"inject_declared":"invalid","declared_ttl_max":true}}}),
        json!({"policy_hash":"c","addons":{"test_context":{"declared_ttl_max":0}}}),
    ];
    let owner = TestContext::default();
    let who = identity("slot:a", "alice");
    let expected: Vec<_> = configs
        .iter()
        .map(|config| {
            owner
                .configure(
                    Some(config),
                    Options {
                        block: false,
                        inject_declared: true,
                        declared_ttl: json!(5),
                    },
                )
                .unwrap();
            let ttl = owner
                .set_declaration(&who, context("run=r;agent=alice"), None, 0.)
                .unwrap();
            let applied = matches!(
                request(&owner, "target.invalid", None, Some(&who), 0.),
                RequestOutcome::Applied { .. }
            );
            json!({"targets":owner.stats(0.).unwrap().target_hosts,"ttl":ttl,"injected":applied})
        })
        .collect();
    let actual = python(
        r#"
import json,sys
import safeyolo.mitm_addons.test_context as module
import safeyolo.core.config_cache as cache
owner=module.TestContext()
module.get_option_safe=lambda name,default:{'test_context_declared_ttl':5,'test_context_inject_declared':True}.get(name,default)
out=[]
for config in json.load(sys.stdin):
    cache.get_or_raise=lambda:config
    cache.addon_section=lambda name:config.get('addons',{}).get(name,{})
    owner._maybe_reload_config()
    out.append(dict(targets=len(owner._target_hosts),ttl=owner._declared_ttl_max(),injected=owner._is_target_host('target.invalid') and owner._inject_declared_enabled()))
print(json.dumps(out))
"#,
        &json!(configs),
    );
    assert_eq!(actual, json!(expected));
    eprintln!(
        "Compared {} actual Python inner Agent API operations and {} dynamic configurations",
        operations.len(),
        configs.len()
    );
}
