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
