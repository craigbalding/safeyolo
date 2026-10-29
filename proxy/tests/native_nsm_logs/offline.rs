//! Explicit retained files exercise the actual CLI without installed state.
use super::{
    correlation::{correlation_rows, only_correlation},
    *,
};

fn save(path: &Path, rows: &[Value]) -> Vec<u8> {
    let bytes = rows
        .iter()
        .map(|row| {
            let text = row.to_string();
            parse_record(&text).unwrap();
            text + "\n"
        })
        .collect::<String>()
        .into_bytes();
    fs::write(path, &bytes).unwrap();
    bytes
}

async fn pivot(root: &Path, paths: &[&Path], kind: &str, id: &str, extra: &[&str]) -> Value {
    let names: Vec<_> = paths.iter().map(|path| path.to_str().unwrap()).collect();
    let mut args = pivot_args(kind, id);
    for name in &names {
        args.extend(["--file", name]);
    }
    args.extend(extra);
    success(root, &args).await
}

fn originals(result: &Value, bytes: &[Vec<u8>]) {
    for entry in result["records"].as_array().unwrap() {
        for location in entry["locations"].as_array().unwrap() {
            let input = location["input"].as_u64().unwrap() as usize - 1;
            let line = location["line"].as_u64().unwrap() as usize - 1;
            assert_eq!(
                entry["record"],
                parse_record(
                    std::str::from_utf8(&bytes[input])
                        .unwrap()
                        .lines()
                        .nth(line)
                        .unwrap()
                )
                .unwrap()
            );
        }
        assert!(
            entry["locations"]
                .as_array()
                .unwrap()
                .contains(&entry["line"])
        );
    }
}

/// Reuse the owned live producer once. Copy exact JSONL bytes, with the
/// exposure on its own and all supporting records in another selected input.
pub(super) async fn assert_native_split(root: &Path, bytes: &[u8], exposure: &Value) {
    let inputs = [root.join("exposure.jsonl"), root.join("support.jsonl")];
    let mut split = [Vec::new(), Vec::new()];
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        let row = parse_record(std::str::from_utf8(line).unwrap()).unwrap();
        let index = usize::from(row != *exposure);
        split[index].extend_from_slice(line);
    }
    for (path, content) in inputs.iter().zip(&split) {
        fs::write(path, content).unwrap();
    }
    let offline_root = root.join("no-installed-instance");
    let paths: Vec<_> = inputs.iter().map(|path| path.to_str().unwrap()).collect();
    for (kind, id) in [
        ("request", exposure["request_id"].as_str().unwrap()),
        (
            "connection",
            exposure["details"]["connection_id"].as_str().unwrap(),
        ),
    ] {
        let args = [
            "logs",
            kind,
            id,
            "--instance",
            exposure["details"]["instance_id"].as_str().unwrap(),
            "--runtime",
            exposure["details"]["runtime_id"].as_str().unwrap(),
            "--agent",
            "alice",
            "--file",
            paths[0],
            "--file",
            paths[1],
            "--lines",
            "1000",
            "--json",
        ];
        let result = success(&offline_root, &args).await;
        let correlation = only_correlation(&result);
        assert_eq!(correlation["status"], "linked", "{result}");
        assert_eq!(correlation["exposure_line"], json!({"input":1,"line":1}));
        assert!(
            correlation["source"]["record_lines"]
                .as_array()
                .unwrap()
                .iter()
                .all(|line| line["input"] == 2)
        );
        assert!(
            result["links"]
                .as_array()
                .unwrap()
                .iter()
                .all(|link| link["status"] == "available")
        );
        originals(&result, &split);
        let ordinary = cli(&offline_root, &args[..args.len() - 1]).await;
        assert!(ordinary.status.success());
        let text = String::from_utf8(ordinary.stdout).unwrap();
        for expected in [
            "Input 1:",
            "Input 2:",
            "physical lines",
            "Prompt exposure correlation",
            "\"input\": 2",
            "linked",
        ] {
            assert!(text.contains(expected), "{text}");
        }
        assert!(!text.contains("amber lighthouse"));
        assert!(!text.contains("synthetic-correlation-credential"));
    }
    assert!(!offline_root.join("config.toml").exists());
    for (path, content) in inputs.iter().zip(&split) {
        assert_eq!(fs::read(path).unwrap(), *content);
    }
    assert_eq!(fs::read(root.join("audit.jsonl")).unwrap(), bytes);
}

#[tokio::test]
async fn selected_inputs_resolve_cross_file_support_with_reused_namespace_and_agent_ids() {
    let root = tempfile::tempdir().unwrap();
    let rows = correlation_rows();
    let paths = [
        root.path().join("one.jsonl"),
        root.path().join("two.jsonl"),
        root.path().join("foreign.jsonl"),
    ];
    let mut foreign = Vec::new();
    for (instance, runtime, agent) in [
        ("I2", "R1", "alice"),
        ("I1", "R2", "alice"),
        ("I1", "R1", "bob"),
    ] {
        for mut row in rows.clone() {
            row["details"]["instance_id"] = json!(instance);
            row["details"]["runtime_id"] = json!(runtime);
            row["agent"] = json!(agent);
            row["details"]["attribution"]["evidence_owner"] = json!(agent);
            row["details"]["attribution"]["trusted_transport_identity"] = json!(agent);
            foreign.push(row);
        }
    }
    let bytes = [
        save(&paths[0], &rows[..6]),
        save(&paths[1], &rows[6..]),
        save(&paths[2], &foreign),
    ];
    let result = pivot(
        root.path(),
        &[&paths[1], &paths[2], &paths[0]],
        "request",
        "F1",
        &[],
    )
    .await;
    assert_eq!(only_correlation(&result)["status"], "linked");
    assert!(
        result["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["record"]["agent"] == "alice"
                && entry["record"]["details"]["instance_id"] == "I1"
                && entry["record"]["details"]["runtime_id"] == "R1")
    );
    originals(
        &result,
        &[bytes[1].clone(), bytes[2].clone(), bytes[0].clone()],
    );
    for (instance, runtime, agent) in [
        ("I2", "R1", "alice"),
        ("I1", "R2", "alice"),
        ("I1", "R1", "bob"),
    ] {
        let result = pivot(
            root.path(),
            &[&paths[0], &paths[1], &paths[2]],
            "connection",
            "C1",
            &[
                "--instance",
                instance,
                "--runtime",
                runtime,
                "--agent",
                agent,
            ],
        )
        .await;
        assert_eq!(only_correlation(&result)["status"], "linked", "{result}");
        assert!(
            result["records"]
                .as_array()
                .unwrap()
                .iter()
                .all(|entry| entry["record"]["agent"] == agent
                    && entry["record"]["details"]["instance_id"] == instance
                    && entry["record"]["details"]["runtime_id"] == runtime)
        );
    }
    // With all agents selected, an unrelated foreign request on reused local
    // connection IDs must not become context for Alice's request.
    let mut bob = rows[..4].to_vec();
    for row in &mut bob {
        row["agent"] = json!("bob");
        row["event_id"] = json!(format!("bob-{}", row["event_id"].as_str().unwrap()));
    }
    save(&paths[2], &bob);
    let mut args = pivot_args("request", "F1");
    args.drain(7..9); // remove --agent alice, retain JSON and namespace options
    for path in &paths {
        args.extend(["--file", path.to_str().unwrap()]);
    }
    let all = success(root.path(), &args).await;
    assert_eq!(only_correlation(&all)["status"], "linked");
    assert!(
        all["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["record"]["agent"] == "alice")
    );
}

#[tokio::test]
async fn overlap_repeated_inputs_and_reformatted_copies_share_evidence_and_keep_all_locations() {
    let root = tempfile::tempdir().unwrap();
    let rows = correlation_rows();
    let a = root.path().join("a.jsonl");
    let b = root.path().join("b.jsonl");
    let a_bytes = save(&a, &rows);
    let reformatted = rows
        .iter()
        .map(|row| {
            let mut row = row.clone();
            row.sort_all_objects();
            format!("  {} \n", row)
        })
        .collect::<String>();
    fs::write(&b, &reformatted).unwrap();
    for paths in [
        [a.as_path(), b.as_path(), a.as_path()],
        [b.as_path(), a.as_path(), a.as_path()],
    ] {
        let result = pivot(root.path(), &paths, "request", "F1", &[]).await;
        let correlation = only_correlation(&result);
        assert_eq!(correlation["status"], "linked", "{result}");
        assert_eq!(
            correlation["source"]["record_lines"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        for side in ["source_transport", "model_transport"] {
            assert_eq!(correlation[side]["flow_lines"].as_array().unwrap().len(), 1);
            assert_eq!(correlation[side]["novelty"].as_array().unwrap().len(), 2);
        }
        assert_eq!(result["search"]["duplicate_namespace_rows"], rows.len() * 2);
        assert_eq!(result["search"]["retained_rows"], rows.len() * 3);
        assert!(
            result["records"]
                .as_array()
                .unwrap()
                .iter()
                .all(|entry| entry["locations"].as_array().unwrap().len() == 3)
        );
        let input_bytes: Vec<_> = paths.iter().map(|path| fs::read(path).unwrap()).collect();
        originals(&result, &input_bytes);
    }
    assert_eq!(fs::read(&a).unwrap(), a_bytes);
    assert_eq!(fs::read_to_string(&b).unwrap(), reformatted);
}

#[tokio::test]
async fn conflicting_event_copies_and_transport_owners_cannot_complete_correlation() {
    let root = tempfile::tempdir().unwrap();
    let a = root.path().join("a.jsonl");
    let b = root.path().join("b.jsonl");
    for case in 0..4 {
        let mut rows = correlation_rows();
        rows[4]["event_id"] = json!("source-event");
        rows[11]["event_id"] = json!("exposure-event");
        let mut conflict = match case {
            0 => rows[4].clone(),
            1 => rows[11].clone(),
            2 => rows[6].clone(),
            _ => rows[3].clone(),
        };
        match case {
            0 => conflict["details"]["evidence_hash"] = json!(format!("sha256:{}", "b".repeat(64))),
            1 => conflict["details"]["source"]["host"] = json!("other.invalid"),
            2 => conflict["details"]["server_connection_id"] = json!("other-server"),
            _ => {
                conflict["event_id"] = json!("later-owner");
                conflict["details"]["client_connection_id"] = json!("other-client");
            }
        }
        let bytes = [save(&a, &rows), save(&b, &[conflict])];
        for paths in [[a.as_path(), b.as_path()], [b.as_path(), a.as_path()]] {
            let result = pivot(root.path(), &paths, "request", "F1", &[]).await;
            assert!(
                result["correlations"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|correlation| correlation["status"] != "linked"),
                "case {case}: {result}"
            );
            assert_eq!(result["search"]["conflicting_namespace_rows"], 2);
            assert!(
                result["records"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|entry| entry["conflicting"] == true)
            );
            assert!(
                result["links"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|link| !link["conflicting_record_lines"].is_null())
                    .all(|link| link["status"] == "unavailable")
            );
        }
        assert_eq!(fs::read(&a).unwrap(), bytes[0]);
        assert_eq!(fs::read(&b).unwrap(), bytes[1]);
    }
}

#[tokio::test]
async fn selected_windows_report_per_input_and_total_copies_without_claiming_missing_support() {
    let root = tempfile::tempdir().unwrap();
    let rows = correlation_rows();
    let a = root.path().join("a.jsonl");
    let b = root.path().join("b.jsonl");
    save(&a, &rows[..6]);
    save(&b, &rows[6..]);
    for (limit, retained) in [("1", 2), ("0", 0), ("100", 12)] {
        let result = pivot(root.path(), &[&a, &b], "request", "F1", &["--lines", limit]).await;
        assert_eq!(result["search"]["retained_rows"], retained);
        assert_eq!(result["search"]["omitted_rows"], rows.len() - retained);
        assert_eq!(result["search"]["lines_read"], rows.len());
        assert_eq!(
            result["search"]["line_limit_per_input"],
            limit.parse::<usize>().unwrap()
        );
        if limit == "1" {
            assert_eq!(only_correlation(&result)["status"], "partial");
        }
        if limit == "0" {
            assert!(result["correlations"].as_array().unwrap().is_empty());
        }
        if limit == "100" {
            assert_eq!(only_correlation(&result)["status"], "linked");
        }
    }
    // A selected file containing only the exposure has unavailable source
    // support, even when a complete export exists beside it on disk.
    save(&b, &rows[11..]);
    let missing = pivot(root.path(), &[&b], "request", "F1", &[]).await;
    assert_eq!(
        only_correlation(&missing)["source"]["status"],
        "unavailable"
    );
    assert_eq!(only_correlation(&missing)["status"], "partial");
}

#[tokio::test]
async fn any_bad_selected_input_aborts_without_echoing_paths_content_or_secrets() {
    let root = tempfile::tempdir().unwrap();
    let a = root.path().join("a.jsonl");
    let b = root.path().join("PRIVATE_DATA-\x1b[31m.jsonl");
    save(&a, &correlation_rows());
    for bytes in [
        b"PRIVATE_DATA\n".to_vec(),
        b"{\"schema_version\":99,\"secret\":\"PRIVATE_DATA\"}\n".to_vec(),
        vec![0xff, b'\n'],
    ] {
        fs::write(&b, bytes).unwrap();
        let mut args = pivot_args("request", "F1");
        args.extend([
            "--file",
            a.to_str().unwrap(),
            "--file",
            b.to_str().unwrap(),
            "--lines",
            "0",
        ]);
        let output = cli(root.path(), &args).await;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("audit input 2:"), "{error}");
        assert!(!error.contains("PRIVATE_DATA"));
        assert!(!error.contains('\x1b'));
    }
    fs::remove_file(&b).unwrap();
    for path in [&b, root.path()] {
        // missing and unreadable directory input
        let output = cli(
            root.path(),
            &[
                "logs",
                "--file",
                a.to_str().unwrap(),
                "--file",
                path.to_str().unwrap(),
                "--json",
            ],
        )
        .await;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("audit input 2:"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE_DATA"));
    }
    save(&b, &correlation_rows());
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&b, fs::Permissions::from_mode(0o000)).unwrap();
    let unreadable = cli(
        root.path(),
        &["logs", "--file", b.to_str().unwrap(), "--json"],
    )
    .await;
    fs::set_permissions(&b, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(!unreadable.status.success());
    assert!(unreadable.stdout.is_empty());
    let error = String::from_utf8(unreadable.stderr).unwrap();
    assert!(error.contains("audit input 1: local audit file could not be opened"));
    assert!(!error.contains("PRIVATE_DATA"));
    let output = cli(
        root.path(),
        &[
            "logs",
            "request",
            "F1",
            "--instance",
            "I1",
            "--runtime",
            "R1",
            "--file",
            b.to_str().unwrap(),
        ],
    )
    .await;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains('\x1b'));
    assert!(text.contains("PRIVATE_DATA-?.jsonl"));
    let json_output = cli(
        root.path(),
        &["logs", "--file", b.to_str().unwrap(), "--json"],
    )
    .await;
    assert!(json_output.status.success());
    let encoded = String::from_utf8(json_output.stdout).unwrap();
    assert!(!encoded.contains('\x1b'));
    assert!(encoded.contains("\\u001b"));
    let raw: Value = serde_json::from_str(&encoded).unwrap();
    assert_eq!(raw["inputs"][0]["file"], b.to_str().unwrap());
}

#[tokio::test]
async fn historical_rows_remain_inspectable_offline_without_becoming_nsm_support() {
    let root = tempfile::tempdir().unwrap();
    let a = root.path().join("history.jsonl");
    let b = root.path().join("exposure.jsonl");
    let rows = correlation_rows();
    let mut legacy = rows[4].clone();
    legacy.as_object_mut().unwrap().remove("schema_version");
    let historical =
        json!({"schema_version":1,"event":"traffic.request","kind":"traffic","request_id":"F0"});
    let bytes = save(&a, &[legacy.clone(), historical.clone()]);
    save(&b, &rows[11..]);
    let raw = success(
        root.path(),
        &["logs", "--file", a.to_str().unwrap(), "--json"],
    )
    .await;
    assert_eq!(raw["inputs"][0]["events"][0]["record"], legacy);
    assert_eq!(raw["inputs"][0]["events"][1]["record"], historical);
    let result = pivot(root.path(), &[&a, &b], "request", "F1", &[]).await;
    assert_eq!(only_correlation(&result)["source"]["status"], "unavailable");
    assert_eq!(result["records"].as_array().unwrap().len(), 1);
    assert_eq!(fs::read(&a).unwrap(), bytes);
}
