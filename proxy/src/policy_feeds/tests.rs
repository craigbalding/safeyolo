use super::*;
use crate::policy::{Effect, NetworkRequest, Policy};

fn source() -> Source {
    Source {
        endpoint: "https://feeds.example/private-key/list?token=synthetic-secret".into(),
        redirect_endpoints: vec![],
        format: Format::Domains,
        scope: Scope::Hostname,
        cadence_seconds: 3600,
        max_age_seconds: 7200,
        timeout_seconds: 10,
        max_bytes: 1024 * 1024,
        min_entries: 1,
        max_entries: 1000,
        max_change_percent: 50,
        retry_seconds: 10,
        max_retry_seconds: 60,
        on_stale: Stale::Deny,
        on_unavailable: Unavailable::Deny,
        metadata: Metadata::None,
    }
}
fn accepted(source: &Source, version: &str, entry: &str, at: u64) -> Snapshot {
    Snapshot {
        source: "test".into(),
        endpoint: source.redacted_endpoint(),
        format: source.format,
        scope: source.scope,
        version: version.into(),
        source_sha256: version.into(),
        acquired_at: at,
        evidence_first_observed_at: at,
        validated_at: at,
        provider_observed_at: None,
        provider_version: None,
        entries: vec![entry.into()],
        config_identity: source.identity(),
    }
}
fn setup(root: &Path, source: &Source) {
    fs::create_dir_all(directory(root, "test")).unwrap();
    let config = Configuration {
        sources: BTreeMap::from([("test".into(), source.clone())]),
    };
    fs::write(
        root.join("policy-feeds.toml"),
        toml::to_string(&config).unwrap(),
    )
    .unwrap();
}
fn decide(policy: &Policy, host: &str, at: u64) -> Effect {
    policy
        .evaluate(
            NetworkRequest {
                agent: Some("alice"),
                host,
                port: Some(443),
                method: "GET",
                path: "/",
            },
            at as f64 * 1000.,
            false,
        )
        .unwrap()
        .effect
}

/// Shared native admission fixture: use the same snapshot producer as feed controls.
pub(crate) fn write_check_feed(root: &Path, version: &str, member: &str, max_age: u64) {
    let mut config = source();
    config.max_age_seconds = max_age;
    setup(root, &config);
    atomic(
        &directory(root, "test").join("state.json"),
        &State {
            config_identity: config.adoption_identity(),
            next_refresh: now() + 86400,
            ..State::default()
        },
    )
    .unwrap();
    atomic(
        &snapshot_path(root, "test").unwrap(),
        &accepted(&config, version, member, now() - 1),
    )
    .unwrap();
}

fn named_policy(root: &Path, negated: bool) -> Policy {
    let condition = if negated {
        "{op='not',condition={op='finding',check='threat'}}"
    } else {
        "{op='finding',check='threat'}"
    };
    let path = root.join("nondefault.toml");
    fs::write(
        &path,
        format!(
            r#"
[hosts.'*']
egress='allow'
[checks.threat]
source_id='selected-threats'
meaning='positive means membership in the selected threat list'
subject='hostname'
result_type='finding'
influences=['hard_exclusion']
implementation_version='feed-membership-1'
configuration_version='test-1'
max_age_seconds=60
source={{kind='feed',name='test'}}
[[check_rules]]
name='threat-exclusion'
host='*'
stage='connect'
influence='hard_exclusion'
priority=0
required=true
when={condition}
on_match='deny'
on_unavailable='approval'
"#
        ),
    )
    .unwrap();
    let mut policy = Policy::from_native_path(&path).unwrap();
    policy.observe_baseline_files(None).unwrap();
    policy
}

fn named_request(host: &str) -> crate::policy::checks::Request<'_> {
    crate::policy::checks::Request {
        agent: Some("alice"),
        host,
        port: 443,
        scheme: "https",
        method: "CONNECT",
        path: None,
        ip: None,
        value: None,
    }
}

#[tokio::test]
async fn named_feed_binds_membership_provenance_reuse_and_true_age_deadline() {
    use crate::policy::checks::{Action, Finding, Stage, Truth};
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let mut source = source();
    source.max_age_seconds = 20;
    source.on_stale = Stale::Retain;
    setup(root, &source);
    let at = now() - 5;
    let snapshot = accepted(&source, "local-A", "bad.example", at);
    atomic(&snapshot_path(root, "test").unwrap(), &snapshot).unwrap();
    let original = fs::read(snapshot_path(root, "test").unwrap()).unwrap();
    let policy = named_policy(root, false);
    let checks = policy.named_checks();
    let deadline = (at + source.max_age_seconds) * 1000;
    for (host, positive) in [
        ("BAD.EXAMPLE.", true),
        ("other.example", false),
        ("sub.bad.example", false),
    ] {
        let request = named_request(host);
        let gathered = checks.collect(&request, Stage::Connect).await.unwrap();
        assert!(checks.versions_current(&gathered).await);
        let entry = &gathered["threat"];
        let result = entry.result.as_ref().unwrap();
        assert_eq!(
            result.subject,
            crate::policy::checks::Subject::Hostname {
                hostname: host.trim_end_matches('.').to_ascii_lowercase()
            }
        );
        assert!(matches!(result.finding, Finding::Finding {positive:p} if p == positive));
        assert_eq!(result.valid_until_ms, Some(deadline));
        assert_eq!(result.source.source_revision, None);
        assert_eq!(result.source.source_observed_at_ms, None);
        assert_eq!(result.source.content_digest.as_deref(), Some("local-A"));
        assert_eq!(
            entry
                .feed_version
                .as_ref()
                .unwrap()
                .snapshot_version
                .as_deref(),
            Some("local-A")
        );
        let reused = checks.collect(&request, Stage::Connect).await.unwrap();
        assert_eq!(reused["threat"].acquisition, "reused_managed_feed_snapshot");
        assert_eq!(
            reused["threat"].result.as_ref().unwrap().collected_at_ms,
            result.collected_at_ms
        );
        for (time, expected) in [
            (
                deadline - 1,
                if positive {
                    Action::Deny
                } else {
                    Action::Allow
                },
            ),
            (deadline, Action::Approval),
            (deadline + 1, Action::Approval),
        ] {
            let evaluation = checks.evaluate(&request, Stage::Connect, reused.clone(), time);
            assert_eq!(evaluation.action, expected);
            if time >= deadline {
                assert_eq!(evaluation.rules[0].truth, Truth::Unavailable);
            }
        }
    }
    assert_eq!(
        fs::read(snapshot_path(root, "test").unwrap()).unwrap(),
        original
    );
}

#[tokio::test]
async fn named_feed_missing_and_unsupported_remain_unavailable_under_negation() {
    use crate::policy::checks::{Action, Stage, Truth};
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let mut source = source();
    source.scope = Scope::DomainSuffix;
    setup(root, &source);
    let missing = named_policy(root, true);
    let request = named_request("bad.example");
    let gathered = missing
        .named_checks()
        .collect(&request, Stage::Connect)
        .await
        .unwrap();
    let result = missing.named_checks().evaluate(
        &request,
        Stage::Connect,
        gathered.clone(),
        now() * 1000 + 999,
    );
    assert_eq!(result.rules[0].truth, Truth::Unavailable);
    assert_eq!(result.action, Action::Approval);
    let mut snapshot = accepted(&source, "suffix-A", "*.bad.example", now() - 2);
    snapshot.provider_observed_at = Some(now() - 10);
    snapshot.provider_version = Some("actual-provider-42".into());
    atomic(&snapshot_path(root, "test").unwrap(), &snapshot).unwrap();
    assert!(!missing.named_checks().versions_current(&gathered).await);
    assert!(missing.baseline_files_changed().unwrap());
    let policy = named_policy(root, false);
    for (host, action) in [
        ("bad.example", Action::Deny),
        ("sub.bad.example", Action::Deny),
        ("bad.example.other", Action::Allow),
        ("192.0.2.1", Action::Approval),
    ] {
        let request = named_request(host);
        let gathered = policy
            .named_checks()
            .collect(&request, Stage::Connect)
            .await
            .unwrap();
        assert!(policy.named_checks().versions_current(&gathered).await);
        if let Some(record) = &gathered["threat"].result {
            assert_eq!(
                record.source.source_revision.as_deref(),
                Some("actual-provider-42")
            );
            assert_eq!(
                record.source.source_observed_at_ms,
                snapshot.provider_observed_at.map(|t| t * 1000)
            );
        }
        assert_eq!(
            policy
                .named_checks()
                .evaluate(
                    &request,
                    Stage::Connect,
                    gathered,
                    crate::policy::current_time_ms() as u64
                )
                .action,
            action
        );
    }
}

#[tokio::test]
async fn named_feed_replacement_rollback_and_configuration_invalidate_held_reused_evidence() {
    use crate::policy::checks::{Action, Stage};
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let mut source = source();
    setup(root, &source);
    let a = accepted(&source, "local-A", "a.example", now() - 2);
    let b = accepted(&source, "local-B", "b.example", now() - 1);
    let path = snapshot_path(root, "test").unwrap();
    for (previous, next) in [(&a, &b), (&b, &a)] {
        atomic(&path, previous).unwrap();
        let policy = named_policy(root, false);
        let request = named_request(&next.entries[0]);
        let first = policy
            .named_checks()
            .collect(&request, Stage::Connect)
            .await
            .unwrap();
        assert_eq!(
            policy
                .named_checks()
                .evaluate(
                    &request,
                    Stage::Connect,
                    first,
                    crate::policy::current_time_ms() as u64
                )
                .action,
            Action::Allow
        );
        let held = policy
            .named_checks()
            .collect(&request, Stage::Connect)
            .await
            .unwrap();
        assert_eq!(held["threat"].acquisition, "reused_managed_feed_snapshot");
        atomic(&path, next).unwrap();
        assert!(!policy.named_checks().versions_current(&held).await);
        assert!(policy.baseline_files_changed().unwrap());
        let reloaded = named_policy(root, false);
        for (host, action) in [
            (&previous.entries[0], Action::Allow),
            (&next.entries[0], Action::Deny),
        ] {
            let request = named_request(host);
            let gathered = reloaded
                .named_checks()
                .collect(&request, Stage::Connect)
                .await
                .unwrap();
            assert!(reloaded.named_checks().versions_current(&gathered).await);
            let result = reloaded.named_checks().evaluate(
                &request,
                Stage::Connect,
                gathered,
                crate::policy::current_time_ms() as u64,
            );
            assert_eq!(result.action, action);
            assert_eq!(
                result.evidence["threat"]
                    .feed_version
                    .as_ref()
                    .unwrap()
                    .snapshot_version
                    .as_ref(),
                Some(&next.version)
            );
            assert_eq!(
                result.evidence["threat"]
                    .result
                    .as_ref()
                    .unwrap()
                    .source
                    .content_digest
                    .as_ref(),
                Some(&next.source_sha256)
            );
        }
    }
    let policy = named_policy(root, false);
    let held = policy
        .named_checks()
        .collect(&named_request("b.example"), Stage::Connect)
        .await
        .unwrap();
    source.max_age_seconds = 1;
    setup(root, &source);
    assert!(!policy.named_checks().versions_current(&held).await);
    assert!(policy.baseline_files_changed().unwrap());
    let expired = named_policy(root, false);
    for host in ["a.example", "b.example"] {
        let request = named_request(host);
        for _ in 0..2 {
            let evidence = expired
                .named_checks()
                .collect(&request, Stage::Connect)
                .await
                .unwrap();
            assert_eq!(
                evidence["threat"].acquisition, "managed_feed_snapshot",
                "expired findings must not be reused"
            );
            assert_eq!(
                expired
                    .named_checks()
                    .evaluate(
                        &request,
                        Stage::Connect,
                        evidence,
                        crate::policy::current_time_ms() as u64
                    )
                    .action,
                Action::Approval
            );
        }
    }
}

#[test]
fn parsers_keep_declared_format_and_match_scope() {
    let mut config = source();
    let data = b"# comment\nBAD.Example.\nbad.example\nother.example # inline\n";
    assert_eq!(
        parse::entries(&config, data).unwrap().entries,
        ["bad.example", "other.example"]
    );
    config.scope = Scope::DomainSuffix;
    assert_eq!(
        parse::entries(&config, data).unwrap().entries,
        ["*.bad.example", "*.other.example"]
    );
    config.format = Format::Wildcard;
    assert_eq!(
        parse::entries(&config, b"*.BAD.example\n").unwrap().entries,
        ["*.bad.example"]
    );
    assert!(parse::entries(&config, b"bad.example\n").is_err());
    config.format = Format::Hosts;
    assert!(config.validate().is_err()); // hosts do not silently become suffixes
    config.scope = Scope::Hostname;
    config.validate().unwrap();
    assert_eq!(parse::entries(&config,b"127.0.0.1 localhost\nff02::1 ip6-allnodes\n0.0.0.0 BAD.example other.example # hosts aliases\n").unwrap().entries,["bad.example","other.example"]);
    for data in [
        b"not-an-address good.example\n".as_slice(),
        b"bad.example\n",
        b"127.0.0.1 localhost malicious/path\n",
    ] {
        assert!(parse::entries(&config, data).is_err(), "{data:?}");
    }
    config.format = Format::Domains;
    for data in [
        "<html>login.example</html>\n",
        "||bad.example^\n",
        "bad.example CNAME .\n",
        "https://shared.example/bad\n",
        "203.0.113.5\n",
        "2001:db8::/32\n",
        "*.bad.example\n",
        "a..example\n",
        "# empty\n",
    ] {
        assert!(
            parse::entries(&config, data.as_bytes()).is_err(),
            "accepted {data}"
        );
    }
    assert_eq!(
        parse::entries(&config, b"bad.example").unwrap().entries,
        ["bad.example"]
    );
    config.max_bytes = 4;
    assert!(parse::entries(&config, b"bad.example\n").is_err());
    config.max_bytes = 1024;
    config.max_entries = 1;
    assert!(parse::entries(&config, b"bad.example\nother.example\n").is_err());
}

#[test]
fn source_change_validation_detects_removal_churn_and_growth() {
    let entries = |values: &[&str]| values.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let original = entries(&["a.example", "b.example", "c.example", "d.example"]);
    assert!(parse::validate_change(&original, &original, 0).is_ok());
    assert!(
        parse::validate_change(
            &original,
            &entries(&["a.example", "b.example", "c.example"]),
            25
        )
        .is_ok()
    );
    assert!(parse::validate_change(&original, &entries(&["a.example"]), 50).is_err());
    assert!(
        parse::validate_change(
            &original,
            &entries(&["e.example", "f.example", "g.example", "h.example"]),
            50
        )
        .is_err()
    );
    assert!(
        parse::validate_change(
            &original,
            &entries(&[
                "a.example",
                "b.example",
                "c.example",
                "d.example",
                "e.example"
            ]),
            20
        )
        .is_ok()
    );
    assert!(
        parse::validate_change(
            &original,
            &entries(&[
                "a.example",
                "b.example",
                "c.example",
                "d.example",
                "e.example"
            ]),
            19
        )
        .is_err()
    );
}

#[test]
fn provider_evidence_time_is_explicit_and_not_retrieval_time() {
    let mut config = source();
    config.metadata = Metadata::Hagezi;
    let parsed = parse::entries(
        &config,
        b"# Last modified: 13 Nov 2026 08:16 UTC\n# Version: 2026.1113.0816.14\nbad.example\n",
    )
    .unwrap();
    let (at, version) = (parsed.provider_observed_at, parsed.provider_version);
    assert_eq!(at, Some(1794557760));
    assert_eq!(version.as_deref(), Some("2026.1113.0816.14"));
    assert!(parse::entries(&config, b"bad.example\n").is_err());
    assert!(parse::entries(&config, b"# Last modified: yesterday\nbad.example\n").is_err());
    config.metadata = Metadata::Stevenblack;
    let parsed = parse::entries(
        &config,
        b"# Date: 08 November 2026 03:20:51 (UTC)\nbad.example\n",
    )
    .unwrap();
    let (at, version) = (parsed.provider_observed_at, parsed.provider_version);
    assert_eq!(at, Some(1794108051));
    assert_eq!(version, None);
    let mut saved = accepted(&config, "v1", "bad.example", now());
    saved.provider_observed_at = Some(100);
    assert!(!saved.usable(&config, now()));
    assert!(!saved.usable(&config, 99));
}

#[test]
fn native_missing_and_expired_sources_deny_without_prompt_and_recover_on_reload() {
    let root = tempfile::tempdir().unwrap();
    let config = source();
    setup(root.path(), &config);
    let path = root.path().join("policy.toml");
    fs::write(&path,"[lists]\nbad = { feed = 'test' }\n[hosts]\n'*' = {egress='allow'}\n'$bad' = {egress='deny'}\n").unwrap();
    let policy = Policy::from_native_path(&path).unwrap();
    assert_eq!(decide(&policy, "ordinary.example", 1000), Effect::Deny);
    let data = accepted(&config, "v1", "bad.example", 1000);
    atomic(&snapshot_path(root.path(), "test").unwrap(), &data).unwrap();
    let policy = Policy::from_native_path(&path).unwrap();
    assert_eq!(decide(&policy, "bad.example", 1000), Effect::Deny);
    assert_eq!(decide(&policy, "ordinary.example", 1000), Effect::Allow);
    assert_eq!(decide(&policy, "ordinary.example", 8199), Effect::Allow);
    assert_eq!(decide(&policy, "ordinary.example", 8200), Effect::Deny);
    assert_eq!(decide(&policy, "ordinary.example", 8201), Effect::Deny);
    let mut retain = config.clone();
    retain.on_stale = Stale::Retain;
    setup(root.path(), &retain);
    let policy = Policy::from_native_path(&path).unwrap();
    assert_eq!(decide(&policy, "bad.example", 9000), Effect::Deny);
    assert_eq!(decide(&policy, "ordinary.example", 9000), Effect::Allow);
    fs::remove_file(snapshot_path(root.path(), "test").unwrap()).unwrap();
    let policy = Policy::from_native_path(&path).unwrap();
    assert_eq!(decide(&policy, "ordinary.example", 9000), Effect::Deny);
}

#[test]
fn credentials_do_not_enter_status_or_authored_policy() {
    let root = tempfile::tempdir().unwrap();
    let config = source();
    setup(root.path(), &config);
    let data = accepted(&config, "v1", "bad.example", now());
    atomic(&snapshot_path(root.path(), "test").unwrap(), &data).unwrap();
    let status = status(root.path()).unwrap().to_string();
    let saved = serde_json::to_string(&data).unwrap();
    for output in [status, saved] {
        assert!(!output.contains("private-key"));
        assert!(!output.contains("synthetic-secret"));
        assert!(output.contains("https://feeds.example/[redacted]"));
    }
    let mut invalid = config.clone();
    invalid.endpoint = "https://user:secret@feeds.example/".into();
    assert!(invalid.validate().is_err());
    invalid.endpoint = "file:///etc/shadow".into();
    assert!(invalid.validate().is_err());
    assert!(source_name("../test").is_err());
}

#[test]
fn atomic_replacement_binds_entries_version_and_provenance_for_concurrent_readers() {
    let root = tempfile::tempdir().unwrap();
    let config = source();
    setup(root.path(), &config);
    let first = accepted(&config, "first", "first.example", 1000);
    let second = accepted(&config, "second", "second.example", 2000);
    let path = snapshot_path(root.path(), "test").unwrap();
    atomic(&path, &first).unwrap();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            for i in 0..60 {
                atomic(&path, if i % 2 == 0 { &second } else { &first }).unwrap();
            }
        });
        for _ in 0..100 {
            let seen = load_list(root.path(), "test").unwrap().snapshot.unwrap();
            assert!(seen == first || seen == second);
        }
    });
    let mut revised = config.clone();
    revised.retry_seconds = 20;
    // A scheduling/validation adjustment preserves accepted evidence.
    assert_eq!(config.identity(), revised.identity());
    revised.endpoint = "https://another.example/different".into();
    setup(root.path(), &revised);
    assert!(load_list(root.path(), "test").unwrap().snapshot.is_none());
}

#[test]
fn native_suffix_feed_covers_apex_and_descendants_without_matching_siblings() {
    let root = tempfile::tempdir().unwrap();
    let mut config = source();
    config.format = Format::Wildcard;
    config.scope = Scope::DomainSuffix;
    setup(root.path(), &config);
    let snapshot = accepted(&config, "v1", "*.bad.example", 1000);
    atomic(&snapshot_path(root.path(), "test").unwrap(), &snapshot).unwrap();
    let path = root.path().join("policy.toml");
    fs::write(
        &path,
        "[lists]\nbad={feed='test'}\n[hosts]\n'*'={egress='allow'}\n'$bad'={egress='deny'}\n",
    )
    .unwrap();
    let policy = Policy::from_native_path(&path).unwrap();
    for host in [
        "bad.example",
        "child.bad.example",
        "deep.child.bad.example",
        "BAD.EXAMPLE.",
        "CHILD.BAD.EXAMPLE.",
    ] {
        assert_eq!(decide(&policy, host, 1000), Effect::Deny, "{host}");
    }
    for host in ["notbad.example", "bad.example.other", "other.example"] {
        assert_eq!(decide(&policy, host, 1000), Effect::Allow, "{host}");
    }
}

#[test]
fn maintained_hosts_feed_preserves_dns_labels_with_underscores() {
    let mut config = source();
    config.format = Format::Hosts;
    assert_eq!(
        parse::entries(
            &config,
            b"0.0.0.0 philadelphia_cbslocal.us.intellitxt.com\n"
        )
        .unwrap()
        .entries,
        ["philadelphia_cbslocal.us.intellitxt.com"]
    );
}

#[test]
fn hosts_format_extracts_named_hosts_from_valid_address_records() {
    let mut config = source();
    config.format = Format::Hosts;
    assert_eq!(
        parse::entries(&config, b"203.0.113.10 named.example alias.example")
            .unwrap()
            .entries,
        ["alias.example", "named.example"]
    );
}

#[test]
fn managed_hostname_rules_match_dns_case_root_dot_and_unicode_aliases() {
    let root = tempfile::tempdir().unwrap();
    let config = source();
    setup(root.path(), &config);
    atomic(
        &snapshot_path(root.path(), "test").unwrap(),
        &accepted(&config, "v1", "xn--bcher-kva.example", 1000),
    )
    .unwrap();
    let path = root.path().join("policy.toml");
    fs::write(
        &path,
        "[lists]\nbad={feed='test'}\n[hosts]\n'*'={egress='allow'}\n'$bad'={egress='deny'}\n",
    )
    .unwrap();
    let policy = Policy::from_native_path(&path).unwrap();
    for host in [
        "xn--bcher-kva.example",
        "XN--BCHER-KVA.EXAMPLE.",
        "bücher.example",
        "bücher.example.",
    ] {
        assert_eq!(decide(&policy, host, 1000), Effect::Deny, "{host}");
    }
    assert_eq!(decide(&policy, "other.example", 1000), Effect::Allow);
}
