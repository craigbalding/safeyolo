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
    listing::assert_native_navigation(root, &[]).await;
    listing::assert_native_navigation(
        &offline_root,
        &inputs.iter().map(|path| path.as_path()).collect::<Vec<_>>(),
    )
    .await;
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
        assert_eq!(correlation["warning"]["status"], "investigate");
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
            "Investigation warning:",
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

/// Keep one real producer's destination indication as the only novelty signal.
/// Every failure control must then lose that signal rather than another valid
/// indication accidentally rescuing the warning.
pub(super) async fn assert_native_warning_controls(root: &Path, rows: &[Value], exposure: &Value) {
    let path = root.join("warning-controls.jsonl");
    let offline = root.join("no-warning-instance");
    let request = exposure["request_id"].as_str().unwrap();
    for side in ["source", "model"] {
        let request_id = if side == "source" {
            &exposure["details"]["source"]["request_id"]
        } else {
            &exposure["request_id"]
        };
        let flow = rows
            .iter()
            .find(|row| row["event"] == "traffic.flow" && row["request_id"] == *request_id)
            .unwrap();
        let signal = rows
            .iter()
            .find(|row| {
                row["details"]["rule"] == "destination.first_observation.v1"
                    && row["details"]["connection_id"] == flow["details"]["server_connection_id"]
            })
            .unwrap();
        let baseline: Vec<_> = rows
            .iter()
            .filter(|row| row["details"]["sensor"] != "connection-history.v1" || *row == signal)
            .cloned()
            .collect();
        let source = baseline
            .iter()
            .position(|row| {
                row["event"] == "security.indicator"
                    && row["details"]["direction"] == "server_to_client"
            })
            .unwrap();
        let indicator = baseline.iter().position(|row| row == signal).unwrap();
        let current = baseline
            .iter()
            .position(|row| row["event_id"] == signal["details"]["novelty"]["current"]["event_id"])
            .unwrap();
        let flow_index = baseline.iter().position(|row| row == flow).unwrap();
        let exposure_index = baseline.iter().position(|row| row == exposure).unwrap();
        let mut cases = vec![("supported", baseline.clone(), true)];
        for (label, index) in [
            ("exposure", exposure_index),
            ("source", source),
            ("novelty", indicator),
            ("current", current),
            ("flow", flow_index),
        ] {
            let mut missing = baseline.clone();
            missing.remove(index);
            cases.push((label, missing, false));
            let mut conflicting = baseline.clone();
            let mut copy = conflicting[index].clone();
            // Indicators and flows do not always carry event IDs. Explicitly
            // claim one shared event before testing incompatible event copies.
            if copy["event_id"].is_null() {
                copy["event_id"] = json!("conflicting-fixture-event");
                conflicting[index]["event_id"] = copy["event_id"].clone();
            }
            copy["summary"] = json!("Conflicting copy of essential evidence");
            conflicting.push(copy);
            cases.push((label, conflicting, false));
        }
        for (index, pointer, replacement) in [
            (source, "/host", json!("wrong-source.invalid")),
            (source, "/request_id", json!("wrong-source-request")),
            (
                source,
                "/details/evidence_hash",
                json!(format!("sha256:{}", "b".repeat(64))),
            ),
            (current, "/event_id", json!("wrong-exact-event")),
            (
                current,
                "/details/client_connection_id",
                json!("wrong-client-owner"),
            ),
            (indicator, "/details/instance_id", json!("wrong-instance")),
            (indicator, "/details/runtime_id", json!("wrong-runtime")),
            (indicator, "/agent", json!("bob")),
            (
                indicator,
                "/details/attribution/attribution_status",
                json!("unavailable"),
            ),
            (indicator, "/details/rule", json!("unrecognized.rule.v1")),
            (
                indicator,
                "/details/rule",
                json!("tls.origin_identity_changed.v1"),
            ),
        ] {
            let mut changed = baseline.clone();
            *changed[index].pointer_mut(pointer).unwrap() = replacement;
            cases.push((pointer, changed, false));
        }
        let mut wrong_run = baseline.clone();
        wrong_run[indicator]["details"]["sandbox_run"] = json!({"agent":"alice","agent_id":"fixture-agent","run_id":"0123456789abcdef0123456789abcdef"});
        cases.push(("wrong recorded run", wrong_run, false));
        let mut no_context = baseline.clone();
        no_context.retain(|row| {
            matches!(
                row["event"].as_str(),
                Some("network.connection" | "traffic.flow" | "security.indicator")
            ) && (row["event"] != "traffic.flow" || row["request_id"] == *request_id)
        });
        cases.push(("other flow and decision context absent", no_context, true));
        let mut partial = baseline.clone();
        let mut unsupported = signal.clone();
        unsupported["event_id"] = json!("unsupported-context-indicator");
        unsupported["details"]["novelty"]["current"]["event_id"] = json!("missing-context-event");
        partial.push(unsupported);
        cases.push(("unavailable additional novelty", partial, true));
        for (label, input, warn) in cases {
            let bytes = save(&path, &input);
            let args = [
                "logs",
                "request",
                request,
                "--instance",
                exposure["details"]["instance_id"].as_str().unwrap(),
                "--runtime",
                exposure["details"]["runtime_id"].as_str().unwrap(),
                "--file",
                path.to_str().unwrap(),
                "--lines",
                "1000",
                "--json",
            ];
            let result = success(&offline, &args).await;
            let correlations = result["correlations"].as_array().unwrap();
            assert_eq!(
                correlations
                    .iter()
                    .any(|entry| entry["warning"]["status"] == "investigate"),
                warn,
                "{side} {label}: {result}"
            );
            if label == "unavailable additional novelty" {
                assert_eq!(only_correlation(&result)["status"], "partial");
                assert!(
                    only_correlation(&result)[&format!("{side}_transport")]["novelty"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|entry| entry["status"] == "unavailable")
                );
            }
            if warn {
                let warning = &only_correlation(&result)["warning"];
                assert_eq!(warning["supported_novelty"].as_array().unwrap().len(), 1);
                let original_line = input.iter().position(|row| row == signal).unwrap() + 1;
                assert_eq!(
                    warning["supported_novelty"][0]["indicator_line"],
                    json!({"input":1,"line":original_line})
                );
                assert!(
                    warning["reason"].as_str().unwrap().contains(
                        signal["details"]["novelty"]["destination"]
                            .as_str()
                            .unwrap()
                    )
                );
            }
            originals(&result, std::slice::from_ref(&bytes));
            let ordinary = cli(&offline, &args[..args.len() - 1]).await;
            assert!(ordinary.status.success());
            assert_eq!(
                String::from_utf8(ordinary.stdout)
                    .unwrap()
                    .contains("Investigation warning:"),
                warn,
                "{side} {label}"
            );
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
    }
    assert!(!offline.exists());
}

#[tokio::test]
async fn warning_requires_the_recorded_rules_previous_or_client_observation() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("rule-support.jsonl");
    for paired in [false, true] {
        for mode in 0..5 {
            let mut rows = correlation_rows();
            let signal_index = if paired { 10 } else { 9 };
            let mut signal = rows[signal_index].clone();
            if paired {
                signal["details"]["rule"] = json!("tls.client_destination_first_observation.v1");
                signal["details"]["indicator_type"] = json!("tls_client_destination_novelty");
                signal["details"]["novelty"]["client"] =
                    rows[9]["details"]["novelty"]["current"].clone();
            } else {
                signal["details"]["rule"] = json!("tls.client_fingerprint_changed.v1");
                signal["details"]["indicator_type"] = json!("tls_client_fingerprint_change");
                let mut previous = rows[7]["details"]["novelty"]["current"].clone();
                previous["client_fingerprint"]["ja3"] = json!("b".repeat(32));
                signal["details"]["novelty"]["previous"] = previous;
            }
            let required = if paired { "client" } else { "previous" };
            match mode {
                1 => signal["details"]["novelty"]["current"]["event_id"] = json!("wrong-current"),
                2 => signal["details"]["novelty"][required]["event_id"] = json!("wrong-support"),
                3 => {
                    signal["details"]["novelty"]
                        .as_object_mut()
                        .unwrap()
                        .remove(required);
                }
                4 => {
                    if paired {
                        signal["details"]["novelty"]["client"] =
                            rows[7]["details"]["novelty"]["current"].clone();
                    } else {
                        rows[0]["details"]["leg"] = json!("proxy_to_upstream");
                        rows[0]["details"]["client_connection_id"] = json!("another-client");
                    }
                }
                _ => {}
            }
            rows.retain(|row| row["details"]["sensor"] != "connection-history.v1");
            rows.push(signal);
            save(&path, &rows);
            let result = pivot(root.path(), &[&path], "request", "F1", &[]).await;
            let correlation = only_correlation(&result);
            assert_eq!(
                correlation["warning"]["status"],
                if mode == 0 {
                    "investigate"
                } else {
                    "unavailable"
                },
                "paired={paired} mode={mode}: {result}"
            );
            let support = &correlation["model_transport"]["novelty"][0]["support"];
            if mode == 0 {
                assert_eq!(support.as_array().unwrap().len(), 2);
                assert!(
                    support
                        .as_array()
                        .unwrap()
                        .iter()
                        .all(|link| link["status"] == "available")
                );
            }
        }
    }
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
        br#"{"schema_version":1,"ts":"2026-10-29T00:00:00Z","event":"ops.fixture","kind":"ops","severity":"low","summary":"PRIVATE_DATA","details":{}}"#.to_vec(),
        br#"{"ts":"2026-10-29T00:00:00Z","event":"ops.fixture","kind":"ops","severity":"low","summary":"PRIVATE_DATA","details":{}}"#.to_vec(),
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
async fn current_control_records_and_validation_diagnostics_do_not_supply_nsm_support() {
    use safeyolo_proxy::audit::{Event, Kind, Settings, Severity, Writer};
    let root = tempfile::tempdir().unwrap();
    let a = root.path().join("controls.jsonl");
    let b = root.path().join("exposure.jsonl");
    let rows = correlation_rows();
    let writer = Writer::new(a.clone(), Settings::default());
    for (name, kind) in [
        ("traffic.request", Kind::Traffic),
        ("ops.fixture", Kind::Ops),
    ] {
        let mut event = Event::new(name, kind, Severity::Low, "Unscoped control");
        event.agent = Some("alice".into());
        event.request_id = Some("F0".into());
        // Even matching reference text cannot make another family NSM evidence.
        event.details = rows[4]["details"].clone().into();
        writer.emit(event).unwrap();
    }
    let mut invalid = Event::validation_fallback(
        "network.connection",
        Kind::Network,
        Severity::Medium,
        "Invalid producer input",
    );
    invalid.agent = Some("alice".into());
    invalid.request_id = Some("F0".into());
    invalid.details = rows[4]["details"].clone().into();
    writer.emit(invalid).unwrap();
    assert!(writer.shutdown(Duration::from_secs(2)).unwrap());
    let bytes = fs::read(&a).unwrap();
    save(&b, &rows[11..]);
    let raw = success(
        root.path(),
        &["logs", "--file", a.to_str().unwrap(), "--json"],
    )
    .await;
    let events = raw["inputs"][0]["events"].as_array().unwrap();
    assert_eq!(events.len(), 3);
    assert!(
        events
            .iter()
            .all(|entry| entry["record"]["schema_version"] == 2)
    );
    let diagnostic = &events[2]["record"];
    assert_eq!(diagnostic["event"], "ops.audit_validation_failed");
    assert_eq!(
        diagnostic["details"],
        json!({"event":"network.connection", "kind":"network", "summary":"Invalid producer input"})
    );
    assert!(diagnostic.get("agent").is_none());
    assert!(diagnostic.get("request_id").is_none());
    let listing = success(
        root.path(),
        &["logs", "list", "--file", a.to_str().unwrap(), "--json"],
    )
    .await;
    assert!(listing["namespaces"].as_array().unwrap().is_empty());
    assert_eq!(listing["search"]["non_nsm_rows"], 3);
    let result = pivot(root.path(), &[&a, &b], "request", "F1", &[]).await;
    assert_eq!(only_correlation(&result)["source"]["status"], "unavailable");
    assert_eq!(result["records"].as_array().unwrap().len(), 1);
    assert_eq!(fs::read(&a).unwrap(), bytes);
}
