//! Catalog-only owned filesystem controls; no watcher, runtime or credentials.
use super::*;
use serde_json::json;

fn definition(name: &str, description: Value) -> String {
    json!({"schema_version":1,"name":name,"description":description}).to_string()
}
fn names(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|service| service["name"].as_str().unwrap())
        .collect()
}
fn directories() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let builtin = root.path().join("builtin");
    let user = root.path().join("user");
    std::fs::create_dir(&builtin).unwrap();
    (root, builtin, user)
}
fn write(directory: &Path, filename: &str, name: &str, description: Value) {
    std::fs::write(directory.join(filename), definition(name, description)).unwrap();
}

#[test]
fn directory_glob_and_override_keep_source_catalog_order() {
    let (_root, builtin, user) = directories();
    write(&builtin, "30.yaml", "alpha", "last builtin".into());
    write(&builtin, "20.yaml", "zulu", "builtin replaced".into());
    write(&builtin, ".yaml", "dot-only", "hidden".into());
    write(&builtin, ".hidden.yaml", "hidden", "hidden".into());
    for ignored in ["bad.yml", "bad.YAML", "bad.yaml.backup", "not-yaml"] {
        std::fs::write(builtin.join(ignored), "malformed: [").unwrap();
    }
    std::fs::create_dir(builtin.join("nested")).unwrap();
    std::fs::write(builtin.join("nested/hidden.yaml"), "malformed: [").unwrap();
    std::fs::create_dir(&user).unwrap();
    write(&user, "10.yaml", "zulu", "user override".into());
    write(&user, "20.yaml", "beta", "user only".into());
    let registry = Registry::from_directories(&builtin, &user).unwrap();
    let available = registry.available_services(&BTreeSet::new());
    assert_eq!(
        names(&available),
        ["hidden", "dot-only", "zulu", "alpha", "beta"]
    );
    assert_eq!(available[2]["description"], "user override");
    assert_eq!(
        registry.source_by_service["zulu"],
        user.join("10.yaml").to_str().unwrap()
    );
    assert_eq!(
        names(&registry.available_services(&BTreeSet::from(["zulu", "not-present"]))),
        ["hidden", "dot-only", "alpha", "beta"]
    );
}

#[test]
fn strict_failures_never_replace_an_accepted_candidate() {
    let (_root, builtin, user) = directories();
    write(&builtin, "00.yaml", "kept", "old".into());
    let previous = Registry::from_directories(&builtin, &user).unwrap();
    assert_eq!(
        names(&previous.available_services(&BTreeSet::new())),
        ["kept"]
    );
    for invalid in [
        "",
        "# only comment\n",
        "- nonmapping",
        "broken: [",
        "schema_version: 2\nname: bad",
        "schema_version: 1\nname: kept",
    ] {
        std::fs::write(builtin.join("99.yaml"), invalid).unwrap();
        assert!(
            Registry::from_directories(&builtin, &user).is_err(),
            "invalid definition was accepted"
        );
        assert_eq!(
            previous.available_services(&BTreeSet::new())[0]["description"],
            "old"
        );
    }
    std::fs::write(builtin.join("99.yaml"), [0xff]).unwrap();
    assert!(Registry::from_directories(&builtin, &user).is_err());
    std::fs::remove_file(builtin.join("99.yaml")).unwrap();
    std::fs::create_dir(builtin.join("unreadable.yaml")).unwrap();
    assert!(
        Registry::from_directories(&builtin, &user).is_err(),
        "a matched directory is not a readable definition"
    );
    std::fs::remove_dir(builtin.join("unreadable.yaml")).unwrap();
    std::os::unix::fs::symlink("missing-target", builtin.join("unreadable.yaml")).unwrap();
    assert!(Registry::from_directories(&builtin, &user).is_err());
    std::fs::remove_file(builtin.join("unreadable.yaml")).unwrap();
    std::fs::create_dir(&user).unwrap();
    write(&user, "a.yaml", "kept", "first override".into());
    write(&user, "b.yaml", "kept", "duplicate".into());
    assert!(Registry::from_directories(&builtin, &user).is_err());
    assert_eq!(
        previous.available_services(&BTreeSet::new())[0]["description"],
        "old"
    );
    std::fs::remove_file(user.join("b.yaml")).unwrap();
    assert_eq!(
        Registry::from_directories(&builtin, &user)
            .unwrap()
            .available_services(&BTreeSet::new())[0]["description"],
        "first override"
    );
}

#[test]
fn builtin_required_user_optional_and_file_sources_rejected() {
    let (root, builtin, user) = directories();
    let missing = root.path().join("missing-builtin");
    assert!(Registry::from_directories(&missing, &user).is_err());
    assert_eq!(
        Registry::from_directories(&builtin, &user)
            .unwrap()
            .services
            .len(),
        0
    );
    std::fs::write(&user, "not a directory").unwrap();
    assert!(Registry::from_directories(&builtin, &user).is_err());
    assert!(Registry::from_directories(&user, &missing).is_err());
    assert!(
        Registry::from_directories(&builtin, &user.join("absent-child"))
            .unwrap()
            .services
            .is_empty()
    );
}

#[test]
fn available_projection_preserves_raw_descriptions_and_capability_order_only() {
    let raw = json!({
        "schema_version":1,"name":"catalog","description":null,"default_host":"api.owned.invalid",
        "auth":{"type":"bearer","header":"Owned-Auth"},
        "capabilities":{
            "z-last-alphabetically":{"description":{"text":"owned description"},"routes":[{"methods":"GET","path":"/owned"}]},
            "a-first-alphabetically":{"description":false},
            "missing-description":{}
        },
        "private_extra":"must-not-project"
    });
    let registry = Registry::from_sources(
        &[
            ("catalog.yaml".into(), raw.to_string()),
            ("next.yaml".into(), "schema_version: 1\nname: next\n".into()),
        ],
        &[],
    )
    .unwrap();
    let actual = registry.available_services(&BTreeSet::new());
    assert_eq!(
        actual,
        json!([
            {"name":"catalog","description":null,"capabilities":[
                {"name":"z-last-alphabetically","description":{"text":"owned description"}},
                {"name":"a-first-alphabetically","description":false},
                {"name":"missing-description","description":""}
            ]},
            {"name":"next","description":"","capabilities":[]}
        ])
    );
    assert_eq!(
        actual[0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["name", "description", "capabilities"]
    );
    assert_eq!(
        actual[0]["capabilities"][0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["name", "description"]
    );
}

#[test]
fn gateway_available_borrows_matching_agent_names_after_successful_view() {
    let registry = Arc::new(
        Registry::from_sources(
            &[
                ("01.yaml".into(), definition("zulu", "one".into())),
                ("02.yaml".into(), definition("alpha", "two".into())),
                ("03.yaml".into(), definition("beta", "three".into())),
            ],
            &[],
        )
        .unwrap(),
    );
    let raw = json!({"gateway":{"token_map":{
        "owned-alice-token":{"agent":"alice","service":"zulu","token":"owned-reference"},
        "owned-bob-token":{"agent":"bob","service":"alpha","token":"owned-reference"}
    }}});
    let snapshot =
        GatewaySnapshot::from_document(raw.as_object().unwrap(), false, Some(registry)).unwrap();
    for (agent, expected) in [
        ("alice", vec!["alpha", "beta"]),
        ("bob", vec!["zulu", "beta"]),
        ("unknown", vec!["zulu", "alpha", "beta"]),
    ] {
        assert!(snapshot.agent_services_json(agent).is_ok());
        assert_eq!(names(&snapshot.available_services(agent)), expected);
    }
    let absent = GatewaySnapshot::from_document(raw.as_object().unwrap(), false, None).unwrap();
    assert!(absent.agent_services_json("alice").is_ok());
    assert_eq!(absent.available_services("alice"), json!([]));
}

#[test]
fn service_view_errors_are_categorical_without_changing_reached_validation() {
    for (gateway, expected) in [
        (
            json!({"token_map":{"owned":{"agent":[],"service":"x","token":"owned-reference"}}}),
            ServiceViewError::Type,
        ),
        (
            json!({"token_map":{"owned":{"agent":"other","service":{},"token":"owned-reference"}}}),
            ServiceViewError::Type,
        ),
        (
            json!({"host_map":{"owned.invalid":[]}}),
            ServiceViewError::Type,
        ),
        (
            json!({"token_map":{"owned":{"agent":"alice","service":7,"token":"owned-reference"}}}),
            ServiceViewError::Compatibility,
        ),
        (
            json!({"token_map":{"owned":{"agent":"alice"}}}),
            ServiceViewError::Compatibility,
        ),
    ] {
        let raw = json!({"gateway":gateway});
        let snapshot =
            GatewaySnapshot::from_document(raw.as_object().unwrap(), false, None).unwrap();
        assert!(matches!(snapshot.agent_services_json("alice"), Err(error) if error == expected));
    }
    let policy = Policy::parse("permissions: []\ngateway:\n  token_map:\n    owned:\n      agent: alice\n      service: x\n      token: owned-reference\n      account: 2026-09-16\n", crate::policy::Format::Yaml).unwrap();
    assert!(matches!(
        policy.gateway().unwrap().agent_services_json("alice"),
        Err(ServiceViewError::Type)
    ));
    assert!(
        policy.gateway().unwrap().agent_services_json("bob").is_ok(),
        "an unreached timestamp must not affect another agent"
    );
    assert_eq!(
        ServiceViewError::Type.to_string(),
        "service view type error"
    );
    assert_eq!(
        ServiceViewError::Compatibility.to_string(),
        "service view unavailable"
    );
}

#[test]
fn strict_directory_candidates_match_seven_actual_source_workflows() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../tests/service_catalog_source.json")).unwrap();
    let mut workflows = 0;
    let mut transitions = 0;
    for row in fixture["loader_rows"].as_array().unwrap() {
        let input = &row["input"];
        if input["name"] == "consumer_rollback_and_no_unchanged_retry" {
            // Publication callbacks and automatic change detection belong to
            // the Runtime join, not this immutable catalog constructor.
            continue;
        }
        workflows += 1;
        let root = tempfile::tempdir().unwrap();
        let mut accepted = Registry::default();
        for (recipe, expected) in input["steps"]
            .as_array()
            .unwrap()
            .iter()
            .zip(row["steps"].as_array().unwrap())
        {
            transitions += 1;
            if let Some(paths) = recipe["remove"].as_array() {
                for path in paths {
                    std::fs::remove_file(root.path().join(path.as_str().unwrap())).unwrap();
                }
            }
            if let Some(paths) = recipe["dirs"].as_array() {
                for path in paths {
                    std::fs::create_dir_all(root.path().join(path.as_str().unwrap())).unwrap();
                }
            }
            if let Some(files) = recipe["files"].as_object() {
                for (relative, contents) in files {
                    let path = root.path().join(relative);
                    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                    let contents = contents
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| contents.to_string());
                    std::fs::write(path, contents).unwrap();
                }
            }
            let candidate =
                Registry::from_directories(&root.path().join("builtin"), &root.path().join("user"));
            assert_eq!(
                candidate.is_err(),
                !expected["error"].is_null(),
                "{} transition {transitions}",
                input["name"]
            );
            if let Ok(candidate) = candidate {
                accepted = candidate;
            }
            let actual: Vec<_> = accepted
                .order
                .iter()
                .map(|name| accepted.services[name].raw.clone())
                .collect();
            assert_eq!(
                Value::Array(actual),
                expected["services"],
                "{}",
                input["name"]
            );
        }
    }
    assert_eq!((workflows, transitions), (7, 10));
}

#[test]
fn directory_problems_are_aggregated_without_file_callbacks() {
    use super::catalog::{ProblemKind, ProblemOrigin};
    let root = tempfile::tempdir().unwrap();
    let builtin = root.path().join("builtin");
    let user = root.path().join("user");
    std::fs::write(&builtin, "owned file").unwrap();
    std::fs::write(&user, "owned file").unwrap();
    let mut calls = 0;
    let attempt = Registry::load_directories(&builtin, &user, &mut |_| calls += 1).unwrap();
    assert!(attempt.metadata.is_empty());
    let error = attempt.result.unwrap_err();
    assert_eq!(calls, 0);
    assert_eq!(
        error.problems.iter().map(|p| p.kind).collect::<Vec<_>>(),
        [
            ProblemKind::MissingBuiltin,
            ProblemKind::NotDirectory,
            ProblemKind::NotDirectory
        ]
    );
    assert!(
        error
            .problems
            .iter()
            .all(|p| p.origin == ProblemOrigin::Directory)
    );
    assert_eq!(
        error.to_string(),
        "service definitions are invalid (0 file problems, 3 directory problems)"
    );
    assert_eq!(format!("{error:?}"), "ServiceLoadError");
    assert_eq!(error.problems[0].path, builtin);
    assert_eq!(error.problems[2].path, user);
}

#[test]
fn metadata_precedes_reads_and_problem_callback_precedes_later_read() {
    let (_root, builtin, user) = directories();
    std::fs::write(builtin.join("10-empty.yaml"), "").unwrap();
    write(&builtin, "20-next.yaml", "before", "owned".into());
    let before = scan_service_files(&builtin, &user).unwrap();
    let mut calls = 0;
    let attempt =
        Registry::load_directories(&builtin, &user, &mut |problem: &ServiceLoadProblem| {
            calls += 1;
            if calls > 1 {
                assert_eq!(problem.path.file_name().unwrap(), "20-next.yaml");
                return;
            }
            assert_eq!(problem.path.file_name().unwrap(), "10-empty.yaml");
            // A callback is reached before the next file is read. Replacing that
            // file with an invalid mapping must create a second later problem.
            std::fs::write(builtin.join("20-next.yaml"), "schema_version: 2\n").unwrap();
        })
        .unwrap();
    assert_eq!(attempt.metadata, before);
    assert_ne!(scan_service_files(&builtin, &user).unwrap(), before);
    assert_eq!(calls, 2);
    assert_eq!(attempt.result.unwrap_err().problems.len(), 2);
}

#[test]
fn metadata_key_is_mtime_and_size_with_optional_absent_directory() {
    use std::time::{Duration, UNIX_EPOCH};
    let (_root, builtin, user) = directories();
    let path = builtin.join("owned.yaml");
    std::fs::write(&path, "same").unwrap();
    let file = std::fs::File::options().write(true).open(&path).unwrap();
    let modified = UNIX_EPOCH - Duration::from_nanos(123_456_789);
    file.set_times(std::fs::FileTimes::new().set_modified(modified))
        .unwrap();
    let before: CatalogMetadata = scan_service_files(&builtin, &user).unwrap();
    assert_eq!(before[&path], (-123_456_789, 4));
    std::fs::write(&path, "diff").unwrap();
    file.set_times(std::fs::FileTimes::new().set_modified(modified))
        .unwrap();
    assert_eq!(scan_service_files(&builtin, &user).unwrap(), before);
    std::fs::write(&path, "larger").unwrap();
    file.set_times(std::fs::FileTimes::new().set_modified(modified))
        .unwrap();
    assert_ne!(scan_service_files(&builtin, &user).unwrap(), before);
    let larger = scan_service_files(&builtin, &user).unwrap();
    file.set_times(std::fs::FileTimes::new().set_modified(UNIX_EPOCH))
        .unwrap();
    assert_ne!(scan_service_files(&builtin, &user).unwrap(), larger);
    std::fs::write(builtin.join("ignored.yml"), "ignored").unwrap();
    std::fs::create_dir(builtin.join("nested")).unwrap();
    std::fs::write(builtin.join("nested/ignored.yaml"), "ignored").unwrap();
    std::os::unix::fs::symlink("absent", builtin.join("dangling.yaml")).unwrap();
    assert_eq!(scan_service_files(&builtin, &user).unwrap().len(), 1);
    std::fs::remove_file(&path).unwrap();
    assert!(scan_service_files(&builtin, &user).unwrap().is_empty());
    std::fs::create_dir(&user).unwrap();
    let empty = scan_service_files(&builtin, &user).unwrap();
    std::fs::remove_dir(&user).unwrap();
    assert_eq!(scan_service_files(&builtin, &user).unwrap(), empty);
}

#[test]
fn source_diagnostic_order_and_continuation_with_contained_writer_failure() {
    use super::catalog::{ProblemKind, ProblemOrigin};
    let fixture: Value =
        serde_json::from_str(include_str!("../../tests/service_catalog_source.json")).unwrap();
    let mut rows = 0;
    for row in fixture["diagnostic_rows"].as_array().unwrap() {
        rows += 1;
        let root = tempfile::tempdir().unwrap();
        let input = &row["input"];
        let put_files = |files: &Value| {
            for (relative, contents) in files.as_object().unwrap() {
                let path = root.path().join(relative);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                let text = contents
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| contents.to_string());
                std::fs::write(path, text).unwrap();
            }
        };
        put_files(&input["initial_files"]);
        let builtin = root.path().join("builtin");
        let user = root.path().join("user");
        let previous = Registry::from_directories(&builtin, &user).unwrap();
        put_files(&input["files"]);
        for path in input["dirs"].as_array().unwrap() {
            std::fs::create_dir_all(root.path().join(path.as_str().unwrap())).unwrap();
        }
        for (path, hex) in input["bytes_hex"].as_object().unwrap() {
            assert_eq!(hex, "ff", "finite source invalid UTF-8 fixture");
            std::fs::write(root.path().join(path), [0xff]).unwrap();
        }
        for (path, target) in input["symlinks"].as_object().unwrap() {
            std::os::unix::fs::symlink(target.as_str().unwrap(), root.path().join(path)).unwrap();
        }
        let writer = crate::audit::Writer::new(root.path().join("audit.jsonl"), Default::default());
        let poison = input["audit_raises"] == true;
        if poison {
            writer.poison_for_test();
        }
        let mut attempts = Vec::new();
        let mut failed_submissions = 0;
        let attempt =
            Registry::load_directories(&builtin, &user, &mut |problem: &ServiceLoadProblem| {
                assert_eq!(problem.origin, ProblemOrigin::File);
                attempts.push(
                    problem
                        .path
                        .strip_prefix(root.path())
                        .unwrap()
                        .to_path_buf(),
                );
                if poison {
                    let event = crate::audit::Event::new(
                        "ops.config_error",
                        crate::audit::Kind::Ops,
                        crate::audit::Severity::Medium,
                        "Owned loader failure",
                    );
                    let error = writer.emit(event).unwrap_err();
                    assert_eq!(error.kind(), crate::audit::ErrorKind::Poisoned);
                    failed_submissions += 1;
                }
            })
            .unwrap();
        let problems = attempt.result.unwrap_err().problems;
        assert_eq!(problems.len(), 10);
        assert_eq!(failed_submissions, if poison { 10 } else { 0 });
        for ((problem, expected), path) in problems
            .iter()
            .zip(row["last_errors"].as_array().unwrap())
            .zip(&attempts)
        {
            let expected_path = expected["path"]
                .as_str()
                .unwrap()
                .strip_prefix("<owned>/")
                .unwrap();
            assert_eq!(path, Path::new(expected_path));
            assert_eq!(
                problem.path.strip_prefix(root.path()).unwrap(),
                Path::new(expected_path)
            );
            match expected_path {
                "builtin/40-missing-name.yaml"
                | "builtin/50-null-capabilities.yaml"
                | "builtin/60-schema.yaml" => {
                    assert_eq!(problem.kind, ProblemKind::NativeSchema);
                    assert_eq!(problem.kind.error_type(), "NativeServiceSchemaError");
                }
                "user/00-parser.yaml" => {
                    assert_eq!(problem.kind, ProblemKind::NativeYaml);
                    assert_eq!(problem.kind.error_type(), "NativeYamlError");
                }
                _ => assert_eq!(
                    problem.kind.error_type(),
                    expected["error_type"].as_str().unwrap()
                ),
            }
            if matches!(
                problem.kind,
                ProblemKind::Empty | ProblemKind::NotMapping | ProblemKind::Duplicate
            ) {
                assert_eq!(problem.message, expected["message"].as_str().unwrap());
            }
        }
        assert_eq!(attempts.len(), 10);
        assert_eq!(previous.services["previous"].raw, row["services"][0]);
        assert!(
            !attempt
                .metadata
                .contains_key(&builtin.join("35-missing.yaml"))
        );
    }
    assert_eq!(rows, 2);
}

#[test]
fn directory_metadata_failure_escapes_before_reads_and_public_loader_preserves_io() {
    let (root, builtin, user) = directories();
    std::fs::write(builtin.join("10-empty.yaml"), "").unwrap();
    let bad = root.path().join("long-target");
    // Creating the symlink is valid; following its single oversized target
    // component fails deterministically without uid-sensitive permission setup.
    std::os::unix::fs::symlink("x".repeat(256), &bad).unwrap();
    for (builtin, user) in [(&builtin, &bad), (&bad, &user)] {
        assert_eq!(
            scan_service_files(builtin, user)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENAMETOOLONG)
        );
        let mut calls = 0;
        let error = Registry::load_directories(builtin, user, &mut |_| calls += 1)
            .err()
            .expect("directory metadata failure escapes the attempt");
        assert_eq!(error.raw_os_error(), Some(libc::ENAMETOOLONG));
        assert_eq!(calls, 0, "initial scan fails before reading definitions");
        let error = Registry::from_directories(builtin, user).unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(libc::ENAMETOOLONG)
        );
    }
}

#[test]
fn absent_non_directory_dangling_looping_and_nul_sources_keep_inner_problem_contract() {
    use super::catalog::ProblemKind;
    let (root, builtin, _) = directories();
    write(&builtin, "owned.yaml", "owned", "owned".into());
    let file = root.path().join("ordinary-file");
    std::fs::write(&file, "owned").unwrap();
    let missing = root.path().join("missing");
    let not_directory = file.join("child");
    let dangling = root.path().join("dangling");
    std::os::unix::fs::symlink("absent", &dangling).unwrap();
    let looping = root.path().join("looping");
    std::os::unix::fs::symlink("looping", &looping).unwrap();
    let nul = root.path().join("nul\0directory");
    for path in [&missing, &not_directory, &dangling, &looping, &nul] {
        let mut calls = 0;
        let attempt = Registry::load_directories(&builtin, path, &mut |_| calls += 1).unwrap();
        assert_eq!(attempt.metadata.len(), 1);
        assert!(attempt.result.unwrap().services.contains_key("owned"));
        let attempt = Registry::load_directories(path, &missing, &mut |_| calls += 1).unwrap();
        let error = attempt.result.unwrap_err();
        assert_eq!(error.problems.len(), 1);
        assert_eq!(error.problems[0].kind, ProblemKind::MissingBuiltin);
        assert_eq!(calls, 0);
    }
    let attempt =
        Registry::load_directories(&builtin, &file, &mut |_| panic!("not a file problem")).unwrap();
    assert_eq!(
        attempt.result.unwrap_err().problems[0].kind,
        ProblemKind::NotDirectory
    );
}

#[test]
fn late_directory_metadata_failure_keeps_reached_callback_without_completed_attempt() {
    let (_root, builtin, user) = directories();
    std::fs::create_dir(&user).unwrap();
    std::fs::write(builtin.join("10-empty.yaml"), "").unwrap();
    let before = scan_service_files(&builtin, &user).unwrap();
    assert_eq!(before.len(), 1);
    let mut observed = Vec::new();
    let result = Registry::load_directories(&builtin, &user, &mut |problem| {
        observed.push(problem.path.clone());
        std::fs::remove_dir(&user).unwrap();
        std::os::unix::fs::symlink("x".repeat(256), &user).unwrap();
    });
    let error = result
        .err()
        .expect("no CatalogLoad/attempt key escapes a late directory error");
    assert_eq!(error.raw_os_error(), Some(libc::ENAMETOOLONG));
    assert_eq!(observed, [builtin.join("10-empty.yaml")]);
}

#[test]
fn per_file_stat_failure_is_omitted_then_remains_an_ordered_file_problem() {
    use super::catalog::{ProblemKind, ProblemOrigin};
    let (_root, builtin, user) = directories();
    let path = builtin.join("10-long.yaml");
    std::os::unix::fs::symlink("x".repeat(256), &path).unwrap();
    write(&builtin, "20-valid.yaml", "valid", "owned".into());
    let metadata = scan_service_files(&builtin, &user).unwrap();
    assert_eq!(metadata.len(), 1);
    assert!(!metadata.contains_key(&path));
    let mut calls = Vec::new();
    let attempt = Registry::load_directories(&builtin, &user, &mut |problem| {
        calls.push(problem.path.clone());
    })
    .unwrap();
    assert_eq!(attempt.metadata, metadata);
    let problems = attempt.result.unwrap_err().problems;
    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].path, path);
    assert_eq!(problems[0].origin, ProblemOrigin::File);
    assert!(matches!(problems[0].kind, ProblemKind::Io(_)));
    assert_eq!(calls, [path]);
}
