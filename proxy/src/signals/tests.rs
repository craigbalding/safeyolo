use super::*;
use crate::coord_rooms::federation::endpoint::{Endpoint, Mode};

fn source() -> Source {
    Source {
        endpoint: Endpoint {
            mode: Mode::Loopback,
            url: "nats://127.0.0.1:4222".into(),
            ca_file: None,
            ca_sha256: None,
            tailscale_node: None,
        },
        username: "fixture".into(),
        credential_file: PathBuf::from("/not-read-by-accept"),
        bucket: "signals".into(),
        keys: "lists.>".into(),
        source_id: "fixture".into(),
        max_bytes: 16384,
        max_signals: 10,
        max_age_seconds: 3600,
        retry_seconds: 1,
        follow: true,
        list: Some("test".into()),
    }
}
fn update(revision: u64, body: &str) -> Update {
    Update {
        source_id: "fixture".into(),
        id: "lists.current".into(),
        revision,
        observed_at: now() - 5,
        expires_at: now() + 60,
        withdrawn: false,
        evidence_refs: vec!["fixture:original".into()],
        evidence: Evidence::List { body: body.into() },
    }
}
fn setup(root: &Path, source: &Source) {
    fs::write(
        root.join("signals.toml"),
        toml::to_string(&Configuration {
            sources: BTreeMap::from([("test".into(), source.clone())]),
            rules: BTreeMap::new(),
        })
        .unwrap(),
    )
    .unwrap();
    fs::write(
        root.join("policy-feeds.toml"),
        r#"[sources.test]
endpoint='https://fixture.invalid/list'
distributed=true
format='domains'
scope='hostname'
cadence_seconds=3600
max_age_seconds=3600
timeout_seconds=1
max_bytes=16384
min_entries=1
max_entries=100
max_change_percent=100
retry_seconds=1
max_retry_seconds=2
on_stale='retain'
on_unavailable='deny'
"#,
    )
    .unwrap();
}
fn ingest(root: &Path, source: &Source, update: &Update) -> Result<bool, Error> {
    accept(
        root,
        "test",
        source,
        &update.id,
        &serde_json::to_vec(update).unwrap(),
    )
}

#[test]
fn malformed_signal_commands_are_rejected() {
    assert!(serde_json::from_value::<Update>(json!({"command":"stop all"})).is_err());
}

#[test]
fn configured_rule_round_trips_through_the_native_toml_reader() {
    let source = source();
    let value = json!({"sources":{"list":source},"rules":{"web":{"source":"list","agents":["alice","bob"],"min_severity":7,"distribution":"debian:trixie","authority":"standing",
        "on_stale":"release","on_inactive":"release","response":{"kind":"list","feeds":{"alice":"quarantine","bob":"approved"},"body":"blocked.test\n"}}}});
    let config: Configuration = serde_json::from_value(value).unwrap();
    let text = toml::to_string(&config).unwrap();
    let parsed = crate::policy::parse_toml_document(&text).unwrap();
    serde_json::from_value::<Configuration>(parsed)
        .unwrap_or_else(|error| panic!("fixture configuration failed: {error}; {text}"));
}

#[test]
fn accepted_list_preserves_age_and_cannot_replay_or_resurrect_a_withdrawal() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let source = source();
    setup(root, &source);
    let mut first = update(1, "bad.test\n");
    ingest(root, &source, &first).unwrap();
    let path = root.join("data/policy-feeds/test/accepted.json");
    let bytes = fs::read(&path).unwrap();
    let snapshot: crate::policy_feeds::Snapshot = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(snapshot.provider_observed_at, Some(first.observed_at));
    assert!(!ingest(root, &source, &first).unwrap());
    assert_eq!(bytes, fs::read(&path).unwrap());
    first.source_id = "forged".into();
    assert!(ingest(root, &source, &first).is_err());
    first.source_id = "fixture".into();
    first.evidence = Evidence::List {
        body: "conflict.test\n".into(),
    };
    assert!(ingest(root, &source, &first).is_err());
    let mut correction = update(2, "fixed.test\n");
    ingest(root, &source, &correction).unwrap();
    correction.revision = 3;
    correction.withdrawn = true;
    ingest(root, &source, &correction).unwrap();
    let retired: crate::policy_feeds::Snapshot =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert!(retired.withdrawn);
    assert!(retired.entries.is_empty());
    assert!(ingest(root, &source, &update(1, "bad.test\n")).is_err());
    assert!(
        serde_json::from_slice::<crate::policy_feeds::Snapshot>(&fs::read(path).unwrap())
            .unwrap()
            .entries
            .is_empty()
    );
}

#[test]
fn rejected_updates_and_replaced_source_keep_the_accepted_view() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let source = source();
    setup(root, &source);
    ingest(root, &source, &update(1, "bad.test\n")).unwrap();
    let path = accepted_path(root, "test", "lists.current");
    let original = fs::read(&path).unwrap();
    for value in [
        update(2, "https://commands.invalid/stop"),
        update(0, "other.test\n"),
    ] {
        assert!(ingest(root, &source, &value).is_err());
    }
    let mut future = update(2, "other.test\n");
    future.observed_at = now() + 60;
    assert!(ingest(root, &source, &future).is_err());
    let mut changed = source.clone();
    changed.keys = "other.>".into();
    setup(root, &changed);
    assert!(ingest(root, &source, &update(2, "other.test\n")).is_err());
    assert_eq!(fs::read(path).unwrap(), original);
}

#[test]
fn source_age_expiry_and_capacity_are_explicit() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let mut source = source();
    source.max_signals = 1;
    setup(root, &source);
    let first = update(1, "bad.test\n");
    assert!(first.fresh(&source, first.observed_at));
    assert!(!first.fresh(&source, first.expires_at));
    ingest(root, &source, &first).unwrap();
    let mut second = first.clone();
    second.id = "lists.second".into();
    assert!(ingest(root, &source, &second).is_err());
    assert_eq!(read_accepted(root, "test", &source).unwrap().len(), 1);
}

#[test]
fn changing_connection_settings_does_not_reset_revision_authority() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let mut source = source();
    setup(root, &source);
    let mut withdrawn = update(3, "bad.test\n");
    withdrawn.withdrawn = true;
    ingest(root, &source, &withdrawn).unwrap();
    source.retry_seconds = 2;
    setup(root, &source);
    assert!(ingest(root, &source, &update(2, "bad.test\n")).is_err());
    assert!(ingest(root, &source, &withdrawn).unwrap());
    assert!(!ingest(root, &source, &withdrawn).unwrap());
}
