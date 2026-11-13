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
