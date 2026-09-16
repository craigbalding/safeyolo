//! Finite load-phase controls using only owned files and the existing parser.
use super::*;
use serde_json::json;

fn error(path: &Path, stage: PolicyLoadStage) -> PolicyLoadError {
    let error = Policy::load_baseline_at(path, None, 0.0).unwrap_err();
    assert_eq!(
        error.stage,
        stage,
        "{}",
        path.file_name().unwrap().to_string_lossy()
    );
    // The existing entry point must retain its precise native error contract.
    let public = Policy::from_path_at(path, 0.0).unwrap_err();
    assert_eq!(public.kind, error.error.kind);
    assert_eq!(public.message, error.error.message);
    assert_eq!(error.to_string(), "baseline policy load failed");
    assert!(!format!("{error:?}").contains(&error.error.message));
    error
}

#[test]
fn owned_file_decode_document_and_null_failures_keep_distinct_phases() {
    use PolicyLoadStage::{Decode, Document, JsonNull, Read};
    let root = tempfile::tempdir().unwrap();
    assert_eq!(
        error(&root.path().join("missing.json"), Read).error.kind,
        ErrorKind::Read
    );
    let directory = root.path().join("directory.json");
    std::fs::create_dir(&directory).unwrap();
    assert_eq!(error(&directory, Read).error.kind, ErrorKind::Read);
    let invalid_utf8 = root.path().join("utf8.yaml");
    std::fs::write(&invalid_utf8, [0xff]).unwrap();
    assert_eq!(error(&invalid_utf8, Read).error.kind, ErrorKind::Read);
    for (filename, contents, stage) in [
        ("broken.json", "{", Decode(Format::Json)),
        ("empty.json", "", Decode(Format::Json)),
        ("broken.yaml", "[invalid", Decode(Format::Yaml)),
        ("broken.toml", "[invalid", Decode(Format::Toml)),
        (
            "normalize.toml",
            "budget=1\nglobal_budget=2\n",
            Decode(Format::Toml),
        ),
        ("null.json", "null", JsonNull),
        ("scalar.json", "42", Document),
        ("scalar.yaml", "42", Document),
        ("sequence.json", "[]", Document),
    ] {
        let path = root.path().join(filename);
        std::fs::write(&path, contents).unwrap();
        assert_eq!(error(&path, stage).error.kind, ErrorKind::Invalid);
    }
    for (filename, contents) in [
        ("empty.yaml", ""),
        ("null.yaml", "null"),
        ("empty.toml", ""),
    ] {
        let path = root.path().join(filename);
        std::fs::write(&path, contents).unwrap();
        assert_eq!(
            Policy::load_baseline_at(&path, None, 0.0)
                .unwrap()
                .baseline_permissions_count(),
            Some(0)
        );
    }
}

#[test]
fn baseline_processing_read_errors_and_addon_defaults_are_not_file_decode_errors() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("policy.json");
    std::fs::write(
        &path,
        json!({"hosts":{"$owned":{"egress":"allow"}},"lists":{"owned":"absent.list"}}).to_string(),
    )
    .unwrap();
    assert_eq!(
        error(&path, PolicyLoadStage::Prepare).error.kind,
        ErrorKind::Read
    );
    std::fs::write(&path, r#"{"permissions":42}"#).unwrap();
    assert_eq!(
        error(&path, PolicyLoadStage::Prepare).error.kind,
        ErrorKind::Invalid
    );
    std::fs::write(&path, "{}").unwrap();
    let addons = root.path().join("addons.yaml");
    std::fs::write(&addons, "permissions: 42").unwrap();
    error(&path, PolicyLoadStage::Prepare);
    // Malformed sibling decoding remains ignored by the original public loader.
    std::fs::write(&addons, "[invalid").unwrap();
    assert_eq!(
        Policy::load_baseline_at(&path, None, 0.0)
            .unwrap()
            .baseline_permissions_count(),
        Some(0)
    );
}

#[test]
fn count_reads_validated_permissions_after_simple_extraction_without_serializing() {
    assert_eq!(Policy::unconfigured().baseline_permissions_count(), None);
    let iam = Policy::parse(r#"{"permissions":[{"action":"network:request","resource":"owned.invalid/*","effect":"allow"},{"action":"network:request","resource":"conditioned.invalid/*","effect":"allow","condition":{"port":443}}]}"#, Format::Json).unwrap();
    assert_eq!(iam.baseline_permissions_count(), Some(2));
    let hosts = Policy::parse(r#"{"hosts":{"allow.invalid":{"egress":"allow"},"deny.invalid":{"egress":"deny"},"budget.invalid":{"rate_limit":3}}}"#, Format::Json).unwrap();
    assert_eq!(hosts.rules.len(), 3);
    assert_eq!(hosts.baseline_permissions_count(), Some(1));
    let typed = Policy::parse(
        "permissions: []\naddons:\n  test_context:\n    unused: 2026-01-02\n",
        Format::Yaml,
    )
    .unwrap();
    assert!(typed.baseline().is_err());
    assert_eq!(typed.baseline_permissions_count(), Some(0));
}

#[test]
fn typed_reload_retains_counter_and_task_owners_only_on_success() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("policy.json");
    std::fs::write(&path, r#"{"hosts":{"owned.invalid":{"rate_limit":10}}}"#).unwrap();
    let previous = Policy::load_baseline_at(&path, None, 0.0)
        .unwrap()
        .with_task_source("permissions: []", Format::Yaml)
        .unwrap();
    let request = NetworkRequest {
        agent: Some("owned"),
        host: "owned.invalid",
        port: Some(443),
        method: "GET",
        path: "/",
    };
    assert_eq!(
        previous.evaluate(request, 0.0, true).unwrap().effect,
        Effect::Allow
    );
    let budgets = previous.budgets.lock().unwrap().clone();
    assert!(!budgets.is_empty());
    std::fs::write(&path, r#"{"permissions":42}"#).unwrap();
    let failed = previous.reload_baseline_at(&path, None, 0.0).unwrap_err();
    assert_eq!(failed.stage, PolicyLoadStage::Prepare);
    assert_eq!(previous.baseline_permissions_count(), Some(1));
    assert_eq!(*previous.budgets.lock().unwrap(), budgets);
    std::fs::write(&path, r#"{"hosts":{"new.invalid":{"egress":"allow"}}}"#).unwrap();
    let accepted = previous.reload_baseline_at(&path, None, 0.0).unwrap();
    assert_eq!(accepted.baseline_permissions_count(), Some(0));
    assert!(Arc::ptr_eq(&accepted.budgets, &previous.budgets));
    assert!(Arc::ptr_eq(&accepted.evaluations, &previous.evaluations));
    assert!(Arc::ptr_eq(
        &accepted.task.as_ref().unwrap().baseline,
        &previous.task.as_ref().unwrap().baseline
    ));
    assert_eq!(*accepted.budgets.lock().unwrap(), budgets);
    assert_eq!(previous.baseline_permissions_count(), Some(1));
}

#[test]
fn existing_frontend_gaps_remain_visible_without_new_admission_rules() {
    let root = tempfile::tempdir().unwrap();
    // The source YAML frontend coerces falsy scalars/empty lists to {}. Native
    // document admission already rejected these; stage information does not fix it.
    for (filename, contents, stage, kind) in [
        (
            "false.yaml",
            "false",
            PolicyLoadStage::Document,
            ErrorKind::Invalid,
        ),
        (
            "zero.yaml",
            "0",
            PolicyLoadStage::Document,
            ErrorKind::Invalid,
        ),
        (
            "list.yaml",
            "[]",
            PolicyLoadStage::Document,
            ErrorKind::Invalid,
        ),
        (
            "infinity.yaml",
            "value: .inf",
            PolicyLoadStage::Decode(Format::Yaml),
            ErrorKind::Unsupported,
        ),
        (
            "infinity.toml",
            "value=inf",
            PolicyLoadStage::Decode(Format::Toml),
            ErrorKind::Unsupported,
        ),
        (
            "nan.json",
            "NaN",
            PolicyLoadStage::Decode(Format::Json),
            ErrorKind::Invalid,
        ),
    ] {
        let path = root.path().join(filename);
        std::fs::write(&path, contents).unwrap();
        assert_eq!(error(&path, stage).error.kind, kind);
    }
}

#[test]
fn frozen_source_load_controls_match_counts_and_reached_failure_phases() {
    use PolicyLoadStage::{Decode, JsonNull, Prepare, Read};
    let fixture: Value =
        serde_json::from_str(include_str!("../../tests/policy_reload_source.json")).unwrap();
    let selected = [
        ("iam_success", None),
        ("host_centric_count_excludes_pre_simple", None),
        ("empty_yaml_is_empty_policy", None),
        ("null_yaml_is_empty_policy", None),
        ("empty_toml_is_empty_policy", None),
        ("null_json_fixed_error", Some(JsonNull)),
        ("missing_file_fixed_error", Some(Read)),
        ("invalid_yaml_fixed_error", Some(Decode(Format::Yaml))),
        ("invalid_json_fixed_error", Some(Decode(Format::Json))),
        ("compile_error_retains_prior", Some(Prepare)),
        ("validation_error_retains_prior", Some(Prepare)),
    ];
    for (name, stage) in selected {
        let row = fixture["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["input"]["name"] == name)
            .unwrap();
        let root = tempfile::tempdir().unwrap();
        let input = &row["input"]["file"];
        let path = root.path().join(input["path"].as_str().unwrap());
        if input["missing"] != true {
            // JSON is a YAML subset for these finite source document recipes.
            let text = input["text"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| input["document"].to_string());
            std::fs::write(&path, text).unwrap();
        }
        let attempts = row["attempts"].as_array().unwrap();
        assert_eq!(attempts.len(), 1, "{name}");
        let event = &attempts[0]["event"];
        match stage {
            None => {
                let loaded = Policy::load_baseline_at(&path, None, 0.0).unwrap();
                assert_eq!(row["return"], true, "{name}");
                assert_eq!(event["event"], "ops.policy_reload", "{name}");
                assert_eq!(
                    loaded.baseline_permissions_count().unwrap() as u64,
                    event["details"]["permissions_count"].as_u64().unwrap(),
                    "{name}"
                );
            }
            Some(stage) => {
                assert_eq!(
                    Policy::load_baseline_at(&path, None, 0.0)
                        .unwrap_err()
                        .stage,
                    stage,
                    "{name}"
                );
                assert_eq!(row["return"], false, "{name}");
                assert_eq!(event["event"], "ops.policy_error", "{name}");
                if stage == Prepare {
                    assert!(
                        event["summary"]
                            .as_str()
                            .unwrap()
                            .starts_with("Baseline policy load failed:"),
                        "{name}"
                    );
                } else {
                    assert_eq!(
                        event["summary"], "Baseline policy file not found or invalid",
                        "{name}"
                    );
                }
            }
        }
    }
    // Submission failures, callbacks, and task-file reload ordering belong to
    // the runtime owner. This component does not emit or publish policy events.
}
