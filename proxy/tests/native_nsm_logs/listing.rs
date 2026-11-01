//! Retained evidence discovery through the actual CLI.

use super::{correlation::correlation_rows, *};

async fn list(root: &Path, paths: &[&Path], extra: &[&str]) -> Value {
    let mut args = vec!["logs", "list", "--json"];
    for path in paths {
        args.extend(["--file", path.to_str().unwrap()]);
    }
    args.extend(extra);
    success(root, &args).await
}

fn entries(value: &Value) -> impl Iterator<Item = &Value> {
    value["namespaces"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|namespace| {
            namespace["agents"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|agent| agent["records"].as_array().unwrap())
        })
}

/// Exercise discovery first, then use only the returned keys for each pivot.
/// Called on the existing live producer's configured and split offline bytes.
pub(super) async fn assert_native_navigation(root: &Path, paths: &[&Path]) {
    let listing = list(root, paths, &["--lines", "1000"]).await;
    let namespace = listing["namespaces"]
        .as_array()
        .unwrap()
        .iter()
        .find(|namespace| {
            namespace["agents"].as_array().unwrap().iter().any(|group| {
                group["agent"] == "alice"
                    && group["records"].as_array().unwrap().iter().any(|record| {
                        record["indicator"]["indicator_type"] == "prompt_injection_exposure"
                    })
            })
        })
        .unwrap();
    let group = namespace["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["agent"] == "alice" && group["context"] == "resolved_agent")
        .unwrap();
    let records = group["records"].as_array().unwrap();
    for event in ["network.connection", "traffic.flow", "security.indicator"] {
        assert!(records.iter().any(|record| record["event"] == event));
    }
    let exposure = records
        .iter()
        .find(|record| record["indicator"]["indicator_type"] == "prompt_injection_exposure")
        .unwrap();
    for (kind, field) in [
        ("request", "request_id"),
        ("connection", "details.connection_id"),
    ] {
        let reference = exposure["references"]
            .as_array()
            .unwrap()
            .iter()
            .find(|reference| reference["kind"] == kind && reference["field"] == field)
            .unwrap();
        let mut args = vec![
            "logs",
            kind,
            reference["id"].as_str().unwrap(),
            "--instance",
            namespace["instance_id"].as_str().unwrap(),
            "--runtime",
            namespace["runtime_id"].as_str().unwrap(),
            "--agent",
            group["agent"].as_str().unwrap(),
            "--lines",
            "1000",
            "--json",
        ];
        for path in paths {
            args.extend(["--file", path.to_str().unwrap()]);
        }
        let pivot = success(root, &args).await;
        assert_eq!(correlation::only_correlation(&pivot)["status"], "linked");
        assert!(
            pivot["records"]
                .as_array()
                .unwrap()
                .iter()
                .any(|record| { record["line"] == exposure["line"] })
        );
    }
    let mut args = vec!["logs", "list", "--lines", "1000"];
    for path in paths {
        args.extend(["--file", path.to_str().unwrap()]);
    }
    let ordinary = cli(root, &args).await;
    assert!(ordinary.status.success());
    let text = String::from_utf8(ordinary.stdout).unwrap();
    for expected in [
        "Retained NSM evidence",
        "Instance:",
        "Runtime:",
        "Agent:",
        "resolved_agent",
        "connection",
        "request",
        "prompt_injection_exposure",
        "Locations:",
        "physical lines",
    ] {
        assert!(text.contains(expected), "{text}");
    }
    assert!(!text.contains("amber lighthouse"));
    assert!(!text.contains("synthetic-correlation-credential"));
}

#[tokio::test]
async fn namespaces_agent_context_and_recorded_references_are_discoverable() {
    let root = tempfile::tempdir().unwrap();
    configure(root.path());
    let mut rows = correlation_rows();
    for (instance, runtime, agent) in [
        ("I2", "R1", "alice"),
        ("I1", "R2", "alice"),
        ("I1", "R1", "bob"),
    ] {
        for mut record in correlation_rows() {
            record["details"]["instance_id"] = json!(instance);
            record["details"]["runtime_id"] = json!(runtime);
            record["agent"] = json!(agent);
            record["details"]["attribution"]["evidence_owner"] = json!(agent);
            record["details"]["attribution"]["trusted_transport_identity"] = json!(agent);
            if agent == "bob" {
                // Event IDs have namespace scope, not agent scope.
                record.as_object_mut().unwrap().remove("event_id");
            }
            rows.push(record);
        }
    }
    let mut unknown = connection("UNKNOWN", "unknown-event");
    rows.push(unknown.clone()); // Name alone must not become trusted context.
    unknown.as_object_mut().unwrap().remove("agent");
    unknown["event_id"] = json!("unattributed-event");
    rows.push(unknown);
    let mut standalone = indicator("unused");
    standalone["details"]
        .as_object_mut()
        .unwrap()
        .remove("connection_id");
    standalone["event_id"] = json!("standalone-indicator");
    rows.push(standalone);
    rows.push(row(
        "ops.fixture",
        json!({"instance_id":"I3", "runtime_id":"R3", "connection_id":"UNSCOPED"}),
    ));
    write_rows(root.path(), &rows);
    let bytes = fs::read(root.path().join("audit.jsonl")).unwrap();
    let result = list(root.path(), &[], &[]).await;
    assert_eq!(result["namespaces"].as_array().unwrap().len(), 3);
    assert_eq!(result["search"]["non_nsm_rows"], 1);
    assert_eq!(result["search"]["conflicting_nsm_records"], 0);
    let standalone = entries(&result)
        .find(|record| record["event_id"] == "standalone-indicator")
        .unwrap();
    assert_eq!(standalone["indicator"]["indicator_type"], "fixture");
    assert!(standalone["references"].as_array().unwrap().is_empty());
    let namespace = result["namespaces"]
        .as_array()
        .unwrap()
        .iter()
        .find(|namespace| namespace["instance_id"] == "I1" && namespace["runtime_id"] == "R1")
        .unwrap();
    let groups = namespace["agents"].as_array().unwrap();
    for (agent, context) in [
        (json!("alice"), "resolved_agent"),
        (json!("bob"), "resolved_agent"),
        (json!("alice"), "unknown"),
        (Value::Null, "unknown"),
    ] {
        assert!(
            groups
                .iter()
                .any(|group| group["agent"] == agent && group["context"] == context)
        );
    }
    let selected = list(
        root.path(),
        &[],
        &["--instance", "I1", "--runtime", "R1", "--agent", "alice"],
    )
    .await;
    assert_eq!(selected["namespaces"].as_array().unwrap().len(), 1);
    assert!(
        selected["namespaces"][0]["agents"]
            .as_array()
            .unwrap()
            .iter()
            .all(|group| group["agent"] == "alice")
    );
    // Every displayed reference drives the accepted actual CLI in its namespace.
    for namespace in result["namespaces"].as_array().unwrap() {
        for group in namespace["agents"].as_array().unwrap() {
            for record in group["records"].as_array().unwrap() {
                for reference in record["references"].as_array().unwrap() {
                    let mut args = vec![
                        "logs",
                        reference["kind"].as_str().unwrap(),
                        reference["id"].as_str().unwrap(),
                        "--instance",
                        namespace["instance_id"].as_str().unwrap(),
                        "--runtime",
                        namespace["runtime_id"].as_str().unwrap(),
                        "--json",
                    ];
                    if let Some(agent) = group["agent"].as_str() {
                        args.extend(["--agent", agent]);
                    }
                    let pivot = success(root.path(), &args).await;
                    assert!(
                        pivot["records"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|entry| entry["line"] == record["line"])
                    );
                }
            }
        }
    }
    let raw = success(root.path(), &["logs", "--json"]).await;
    assert!(
        raw["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["details"]["connection_id"] == "UNSCOPED")
    );
    assert_eq!(fs::read(root.path().join("audit.jsonl")).unwrap(), bytes);
}

#[tokio::test]
async fn copies_keep_locations_and_conflicting_events_and_owners_stay_separate() {
    let root = tempfile::tempdir().unwrap();
    configure(root.path());
    let mut rows = correlation_rows();
    let mut conflict = rows[0].clone();
    conflict["summary"] = json!("Conflicting event copy");
    rows.push(conflict);
    let mut connection_owner = rows[3].clone();
    connection_owner["event_id"] = json!("another-event");
    connection_owner["details"]["client_connection_id"] = json!("OTHER");
    rows.push(connection_owner);
    let mut flow_owner = rows[6].clone();
    flow_owner["details"]["server_connection_id"] = json!("OTHER");
    rows.push(flow_owner);
    rows.push(rows[0].clone());
    write_rows(root.path(), &rows);
    let path = root.path().join("audit.jsonl");
    let bytes = fs::read(&path).unwrap();
    let result = list(root.path(), &[&path, &path], &[]).await;
    assert_eq!(result["search"]["distinct_nsm_records"], rows.len() - 1);
    assert_eq!(result["search"]["duplicate_nsm_rows"], rows.len() + 1);
    assert_eq!(result["search"]["conflicting_nsm_records"], 6);
    for record in entries(&result) {
        let locations = record["locations"].as_array().unwrap();
        assert!(locations.len() >= 2);
        for location in locations {
            assert!(matches!(location["input"].as_u64(), Some(1 | 2)));
            let original = &rows[location["line"].as_u64().unwrap() as usize - 1];
            assert_eq!(record["summary"], original["summary"]);
            assert_eq!(record["event_id"], original["event_id"]);
        }
    }
    for group in result["namespaces"][0]["agents"].as_array().unwrap() {
        assert!(
            group["records"]
                .as_array()
                .unwrap()
                .iter()
                .all(|record| { record["conflicting"] == (group["context"] == "conflicting") })
        );
    }
    // Configured listings also collapse copies; configured pivots keep their
    // existing representation. Conflict markings are discovery evidence only.
    let configured = list(root.path(), &[], &[]).await;
    assert_eq!(configured["search"]["distinct_nsm_records"], rows.len() - 1);
    assert_eq!(configured["search"]["duplicate_nsm_rows"], 1);
    assert_eq!(configured["search"]["conflicting_nsm_records"], 6);
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[tokio::test]
async fn listing_windows_are_per_input_and_precede_namespace_selection() {
    let root = tempfile::tempdir().unwrap();
    configure(root.path());
    let path = root.path().join("audit.jsonl");
    fs::write(&path, "").unwrap();
    let empty = list(root.path(), &[], &[]).await;
    assert!(empty["namespaces"].as_array().unwrap().is_empty());
    assert_eq!(empty["inputs"][0]["first_line"], Value::Null);
    let mut rows = vec![connection("FIRST", "first")];
    rows.extend((0..104).map(|index| {
        let mut row = connection(&format!("C{index}"), &format!("E{index}"));
        row["details"]["instance_id"] = json!("I2");
        row["agent"] = json!("bob");
        row
    }));
    write_rows(root.path(), &rows);
    let bytes = fs::read(&path).unwrap();
    let default = list(root.path(), &[&path, &path], &[]).await;
    assert_eq!(default["search"]["retained_rows"], 200);
    assert_eq!(default["search"]["omitted_rows"], 10);
    assert_eq!(default["search"]["distinct_nsm_records"], 100);
    assert_eq!(default["search"]["duplicate_nsm_rows"], 100);
    assert_eq!(default["inputs"][0]["first_line"], 6);
    let missing = list(root.path(), &[], &["--instance", "I1"]).await;
    assert!(missing["namespaces"].as_array().unwrap().is_empty());
    let expanded = list(root.path(), &[], &["--lines", "1000", "--instance", "I1"]).await;
    assert_eq!(expanded["search"]["distinct_nsm_records"], 1);
    let agent = list(root.path(), &[], &["--agent", "alice"]).await;
    assert_eq!(agent["search"]["agent_rows"], 1);
    assert_eq!(agent["inputs"][0]["first_line"], 1);
    for extra in [vec!["--lines", "0"], vec!["--agent", "absent"]] {
        let empty = list(root.path(), &[], &extra).await;
        assert!(empty["namespaces"].as_array().unwrap().is_empty());
        assert_eq!(empty["search"]["retained_rows"], 0);
    }
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[tokio::test]
async fn listing_preserves_exact_ids_and_escapes_both_output_modes() {
    let root = tempfile::tempdir().unwrap();
    configure(root.path());
    let id = format!("C\u{1b}[2J\n\u{202e}é\\\"{}", "x".repeat(300));
    let mut record = connection(&id, "E\u{1b}\n");
    record["agent"] = json!("unknown\n\u{202e}");
    record["summary"] = json!("summary\n\u{1b}[2J\u{202e}");
    record["details"]["instance_id"] = json!("I\n\u{202e}");
    record["details"]["runtime_id"] = json!("R\u{1b}");
    write_rows(root.path(), &[record.clone()]);
    let bytes = fs::read(root.path().join("audit.jsonl")).unwrap();
    for json in [false, true] {
        let mut args = vec!["logs", "list"];
        if json {
            args.push("--json");
        }
        let output = cli(root.path(), &args).await;
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.is_ascii());
        assert!(!text.contains('\u{1b}'));
        assert!(text.contains("\\u001b"));
        assert!(text.contains("\\u202e"));
        assert!(text.contains(&"x".repeat(300)));
        if json {
            let listing: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(
                listing["namespaces"][0]["instance_id"],
                record["details"]["instance_id"]
            );
            assert_eq!(entries(&listing).next().unwrap()["references"][0]["id"], id);
        } else {
            assert!(text.contains("Context: unknown"));
        }
    }
    let pivot = success(
        root.path(),
        &[
            "logs",
            "connection",
            &id,
            "--instance",
            record["details"]["instance_id"].as_str().unwrap(),
            "--runtime",
            record["details"]["runtime_id"].as_str().unwrap(),
            "--json",
        ],
    )
    .await;
    assert_eq!(pivot["records"][0]["record"], record);
    assert_eq!(fs::read(root.path().join("audit.jsonl")).unwrap(), bytes);
}

#[tokio::test]
async fn invalid_selected_inputs_fail_listing_without_partial_output() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("invalid\u{1b}SECRET.jsonl");
    let valid = root.path().join("valid.jsonl");
    fs::write(&valid, connection("C", "E").to_string() + "\n").unwrap();
    for bytes in [
        b"{SECRET".as_slice(),
        b"\xff\n",
        b"{\"schema_version\":99,\"SECRET\":true}\n",
        br#"{"schema_version":1,"ts":"2026-10-29T00:00:00Z","event":"ops.fixture","kind":"ops","severity":"low","summary":"SECRET","details":{}}"#,
        br#"{"ts":"2026-10-29T00:00:00Z","event":"ops.fixture","kind":"ops","severity":"low","summary":"SECRET","details":{}}"#,
    ] {
        fs::write(&path, bytes).unwrap();
        let output = cli(
            root.path(),
            &[
                "logs",
                "list",
                "--file",
                valid.to_str().unwrap(),
                "--file",
                path.to_str().unwrap(),
                "--lines",
                "0",
                "--agent",
                "absent",
                "--json",
            ],
        )
        .await;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("audit input 2:"), "{error}");
        assert!(!error.contains("SECRET"));
        assert!(!error.contains('\u{1b}'));
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
    fs::remove_file(&path).unwrap();
    let output = cli(
        root.path(),
        &["logs", "list", "--file", path.to_str().unwrap(), "--json"],
    )
    .await;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("audit input 1:")
    );
    assert!(!root.path().join("config.toml").exists());
}
