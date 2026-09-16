use super::*;

fn invalid_catalog(directory: &Path) -> Config {
    let mut settings = config(directory);
    let builtin = directory.join("builtin");
    let user = directory.join("user");
    std::fs::create_dir(&builtin).unwrap();
    std::fs::create_dir(&user).unwrap();
    install_catalog(&builtin, false);
    // Deliberately create files in reverse order. A valid builtin prefix must
    // not be published, and both user failures must be inspected and audited.
    std::fs::write(user.join("02-mapping.yaml"), "[]").unwrap();
    std::fs::write(user.join("01-empty.yaml"), "").unwrap();
    settings.gateway_builtin_services_dir = Some(builtin);
    settings.gateway_services_dir = Some(user);
    write_json(
        settings.policy_file.as_ref().unwrap(),
        &policy_document(false),
    );
    settings
}

fn errors(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|event| event["event"] == "ops.config_error")
        .collect()
}

#[tokio::test]
async fn startup_catalog_rejection_drains_ordered_file_diagnostics() {
    let directory = tempfile::tempdir().unwrap();
    let settings = invalid_catalog(directory.path());
    let result = Proxy::start(settings.clone()).await;
    assert!(result.is_err());
    assert!(!settings.readiness_file.exists());
    assert!(!directory.path().join("alice.sock").exists());
    let rows = errors(settings.audit_log_path.as_ref().unwrap());
    assert_eq!(rows.len(), 2);
    for (row, (file, class, message)) in rows.iter().zip([
        ("01-empty.yaml", "ValueError", "service definition is empty"),
        (
            "02-mapping.yaml",
            "TypeError",
            "service definition must be a YAML mapping",
        ),
    ]) {
        assert_eq!(row["kind"], "ops");
        assert_eq!(row["severity"], "medium");
        assert_eq!(row["addon"], "service-loader");
        assert_eq!(
            row["summary"],
            format!("Service definition {file} failed to load")
        );
        assert_eq!(
            row["details"],
            json!({"file":file,"error_type":class,"error":message})
        );
        assert_eq!(
            row["details"]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["file", "error_type", "error"]
        );
        for absent in ["request_id", "agent", "host", "decision", "attribution"] {
            assert!(!row.as_object().unwrap().contains_key(absent));
        }
    }
}

#[test]
fn diagnostic_submission_failure_keeps_all_file_problems_and_directory_omissions() {
    let directory = tempfile::tempdir().unwrap();
    let settings = invalid_catalog(directory.path());
    let writer = audit::Writer::new(directory.path().join("poisoned-audit"), Default::default());
    writer.poison_for_test();
    let mut attempted = Vec::new();
    let load = services::Registry::load_directories(
        settings.gateway_builtin_services_dir.as_ref().unwrap(),
        settings.gateway_services_dir.as_ref().unwrap(),
        &mut |problem| {
            attempted.push(problem.path.file_name().unwrap().to_owned());
            record_service_problem(&writer, problem);
        },
    );
    assert!(load.result.is_err());
    assert_eq!(
        attempted,
        [
            std::ffi::OsString::from("01-empty.yaml"),
            std::ffi::OsString::from("02-mapping.yaml")
        ]
    );
    assert!(!directory.path().join("poisoned-audit").exists());

    let missing = directory.path().join("missing-builtin");
    let non_directory = directory.path().join("user-file");
    std::fs::write(&non_directory, "owned file").unwrap();
    let mut calls = 0;
    let load = services::Registry::load_directories(&missing, &non_directory, &mut |_| calls += 1);
    assert!(load.result.is_err());
    assert_eq!(calls, 0);
    assert!(load.metadata.is_empty());
}
