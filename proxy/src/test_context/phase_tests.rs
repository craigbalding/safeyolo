use super::*;
use crate::policy::Format;

fn owner(block: bool, inject: bool) -> TestContext {
    let owner = TestContext::default();
    owner
        .configure(
            Some(&json!({"policy_hash":"phase","addons":{"test_context":{
                "target_hosts":["target.invalid"],"inject_declared":inject
            }}})),
            Options {
                block,
                ..Options::default()
            },
        )
        .unwrap();
    owner
}
fn request() -> Request<'static> {
    Request {
        host: "target.invalid",
        prior_response: false,
        identity: None,
        metadata_agent: Some("alice"),
    }
}
fn header() -> Vec<Header> {
    vec![(HEADER.into(), b"run=phase;agent=claim;test=first".to_vec())]
}
fn counts(owner: &TestContext) -> [u64; 5] {
    let stats = &owner.lock().unwrap().stats;
    [
        stats.checks_total,
        stats.allowed_total,
        stats.blocked_total,
        stats.warned_total,
        stats.declared_injections_total,
    ]
}
fn applied(result: &Result<RequestOutcome>) -> &AppliedContext {
    match result {
        Ok(RequestOutcome::Applied { applied }) => applied,
        _ => panic!("expected selected context"),
    }
}

#[test]
fn early_response_or_cancellation_drops_preparation_without_request_effect_counts() {
    let owner = owner(true, false);
    for _ in 0..2 {
        let mut headers = header();
        let prepared = owner.prepare_request(request(), &mut headers, 0.).unwrap();
        assert!(headers.is_empty(), "head containment does not wait for EOM");
        assert_eq!(applied(prepared.result()).source, ContextSource::Header);
        assert_eq!(counts(&owner), [0; 5]);
        // The root retains this private claim, but publishes no metadata before
        // begin. Source early streamed response: no request hook, no counters.
        drop(prepared);
        assert_eq!(counts(&owner), [0; 5]);
    }
}

#[test]
fn decode_or_escaped_audit_failure_retains_begun_metadata_and_checks_only() {
    let owner = owner(true, false);
    let prepared = owner.prepare_request(request(), &mut header(), 0.).unwrap();
    let application = prepared.begin().unwrap();
    assert_eq!(counts(&owner), [1, 0, 0, 0, 0]);
    let response_context = applied(application.result()).clone();
    assert_eq!(response_context.source, ContextSource::Header);
    // Source invalid gzip request leaves metadata eligible for response even
    // though allowed remains zero. This models dropping after decoder failure,
    // not replacing its real body decoder or the already retained wire proof.
    drop(application);
    assert_eq!(
        response_context.context,
        Context::parse("run=phase;agent=claim;test=first").unwrap()
    );
    assert_eq!(counts(&owner), [1, 0, 0, 0, 0]);
    let application = owner
        .prepare_request(request(), &mut header(), 0.)
        .unwrap()
        .begin()
        .unwrap();
    drop(application); // a callback that escapes before the source counter step
    assert_eq!(counts(&owner), [2, 0, 0, 0, 0]);
}

#[test]
fn terminal_submission_commits_once_and_keeps_the_selected_declaration_after_reload() {
    let owner = owner(true, true);
    let identity = TrustedIdentity::new("owned-source", "alice").unwrap();
    let original = Context::parse("run=phase;agent=claim;test=original").unwrap();
    owner
        .set_declaration(&identity, original.clone(), None, 0.)
        .unwrap();
    let prepared = owner
        .prepare_request(
            Request {
                identity: Some(&identity),
                ..request()
            },
            &mut Vec::new(),
            0.,
        )
        .unwrap();
    assert_eq!(applied(prepared.result()).source, ContextSource::Declared);
    assert_eq!(counts(&owner), [0; 5]);
    owner
        .set_declaration(
            &identity,
            Context::parse("run=new;agent=claim").unwrap(),
            None,
            0.,
        )
        .unwrap();
    owner.clear_declaration(&identity).unwrap();
    let policy = Policy::parse_at(
        "addons:\n  test_context:\n    target_hosts: []\n    inject_declared: false\n",
        Format::Yaml,
        0.,
    )
    .unwrap();
    // A different real request updates current targets after this selection.
    assert!(matches!(
        owner
            .request_current(Some(&policy), request(), &mut Vec::new(), 0.)
            .unwrap(),
        RequestOutcome::NotTargetHost
    ));
    let application = prepared.begin().unwrap();
    assert_eq!(applied(application.result()).context, original);
    assert_eq!(counts(&owner), [1, 0, 0, 0, 0]);
    assert!(matches!(
        application.finish().unwrap(),
        RequestOutcome::Applied { .. }
    ));
    assert_eq!(counts(&owner), [1, 1, 0, 0, 1]);
    // A normal audit sink failure is swallowed by source submission; root still
    // finishes and separately retains its evidence error marker.
    let application = owner
        .prepare_request(request(), &mut header(), 0.)
        .unwrap()
        .begin()
        .unwrap();
    assert_eq!(counts(&owner), [2, 1, 0, 0, 1]);
    application.finish().unwrap();
    assert_eq!(counts(&owner), [2, 2, 0, 0, 1]);
}

#[test]
fn warnings_and_immediate_head_blocks_commit_only_after_their_decision_audit() {
    for block in [false, true] {
        let owner = owner(block, false);
        let prepared = owner
            .prepare_request(request(), &mut Vec::new(), 0.)
            .unwrap();
        assert!(matches!(prepared.result(), Ok(RequestOutcome::Block { .. })) == block);
        assert_eq!(counts(&owner), [0; 5]);
        let application = prepared.begin().unwrap(); // head for D55 Block; EOM for Warn
        assert_eq!(counts(&owner), [1, 0, 0, 0, 0]);
        drop(application); // a decision callback that escapes leaves checks only
        assert_eq!(counts(&owner), [1, 0, 0, 0, 0]);
        let application = owner
            .prepare_request(request(), &mut Vec::new(), 0.)
            .unwrap()
            .begin()
            .unwrap();
        application.finish().unwrap();
        assert_eq!(
            counts(&owner),
            if block {
                [2, 0, 1, 0, 0]
            } else {
                [2, 0, 0, 1, 0]
            }
        );
    }
    let owner = owner(true, false);
    let mut malformed = vec![(HEADER.into(), b"malformed".to_vec())];
    let prepared = owner
        .prepare_request(
            Request {
                host: "other.invalid",
                ..request()
            },
            &mut malformed,
            0.,
        )
        .unwrap();
    assert!(matches!(
        prepared.result(),
        Ok(RequestOutcome::Warn {
            reason: Reason::MalformedOptionalContext,
            ..
        })
    ));
    prepared.begin().unwrap().finish().unwrap();
    assert_eq!(counts(&owner), [1, 0, 0, 1, 0]);
}

#[test]
fn precheck_target_errors_count_zero_and_postcheck_lookup_errors_wait_for_begin() {
    let owner = owner(true, true);
    let policy = Policy::parse_at(
        "addons:\n  test_context:\n    target_hosts: [2030-01-02]\n",
        Format::Yaml,
        0.,
    )
    .unwrap();
    let mut headers = header();
    let error = match owner.prepare_request_current(Some(&policy), request(), &mut headers, 0.) {
        Err(error) => error,
        Ok(_) => panic!("expected reached target error"),
    };
    assert_eq!(error.kind(), ContextErrorKind::Attribute);
    assert_eq!(headers, header());
    assert_eq!(counts(&owner), [0; 5]);
    let identity = TrustedIdentity::new("owned-source", "alice").unwrap();
    // Source accepts finite TTL/clock values whose addition overflows. The
    // reached remaining-TTL conversion then raises Overflow after checks.
    let huge: Number = format!("1{}", "0".repeat(308)).parse().unwrap();
    owner
        .configure(
            Some(&json!({"policy_hash":"lookup","addons":{"test_context":{
                "target_hosts":["target.invalid"],"inject_declared":true,"declared_ttl_max":huge
            }}})),
            Options::default(),
        )
        .unwrap();
    owner
        .set_declaration(
            &identity,
            Context::parse("run=r;agent=a").unwrap(),
            None,
            1e308,
        )
        .unwrap();
    let prepare = || {
        owner
            .prepare_request(
                Request {
                    identity: Some(&identity),
                    ..request()
                },
                &mut Vec::new(),
                0.,
            )
            .unwrap()
    };
    let dropped = prepare();
    assert!(matches!(dropped.result(), Err(error) if error.kind()==ContextErrorKind::Overflow));
    drop(dropped);
    assert_eq!(counts(&owner), [0; 5]);
    let application = prepare().begin().unwrap();
    assert_eq!(counts(&owner), [1, 0, 0, 0, 0]);
    assert!(matches!(application.finish(), Err(error) if error.kind()==ContextErrorKind::Overflow));
    assert_eq!(counts(&owner), [1, 0, 0, 0, 0]);
    assert!(
        matches!(owner.request(Request{identity:Some(&identity),..request()}, &mut Vec::new(),0.),Err(error) if error.kind()==ContextErrorKind::Overflow)
    );
    assert_eq!(counts(&owner), [2, 0, 0, 0, 0]);
}

#[test]
fn independently_selected_requests_share_counts_without_reusing_completion_permits() {
    let owner = owner(true, false);
    let first = owner.prepare_request(request(), &mut header(), 0.).unwrap();
    let second = owner
        .clone()
        .prepare_request(request(), &mut header(), 0.)
        .unwrap();
    let first = first.begin().unwrap();
    let second = second.begin().unwrap();
    assert_eq!(counts(&owner), [2, 0, 0, 0, 0]);
    second.finish().unwrap();
    first.finish().unwrap();
    assert_eq!(counts(&owner), [2, 2, 0, 0, 0]);
    let prepared = owner
        .prepare_request(
            Request {
                host: "other.invalid",
                ..request()
            },
            &mut Vec::new(),
            0.,
        )
        .unwrap();
    prepared.begin().unwrap().finish().unwrap();
    let prepared = owner
        .prepare_request(
            Request {
                prior_response: true,
                ..request()
            },
            &mut header(),
            f64::NAN,
        )
        .unwrap();
    prepared.begin().unwrap().finish().unwrap();
    assert_eq!(counts(&owner), [2, 2, 0, 0, 0]);
}
