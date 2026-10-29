use super::*;

fn flow(request: &str, client: &str, server: &str) -> Value {
    let mut result = row(
        "traffic.flow",
        json!({"instance_id":"I1","runtime_id":"R1",
        "client_connection_id":client,"server_connection_id":server}),
    );
    result["request_id"] = json!(request);
    result
}

fn upstream(id: &str, event: &str, client: &str) -> Value {
    let mut result = connection(id, event);
    result["details"]["leg"] = json!("proxy_to_upstream");
    result["details"]["client_connection_id"] = json!(client);
    result
}

fn first_observation(client: bool, connection: &str, event: &str) -> Value {
    let mut result = indicator(connection);
    result["details"]["sensor"] = json!("connection-history.v1");
    result["details"]["novelty"] = json!({
        "history_scope":"runtime_fifo","history_capacity":4096,"verification_name":null,
        "current":{"connection_id":connection,"event_id":event,"cert_sha256":null,"spki_sha256":null},
        "previous":null});
    if client {
        result["details"]["indicator_type"] = json!("tls_client_fingerprint_novelty");
        result["details"]["novelty"]["current"]["client_fingerprint"] = json!({
            "ja3":"a".repeat(32),"ja4":"t13d1516h2_8daaf6152771_e5627efa2ab1"});
    } else {
        result["details"]["indicator_type"] = json!("destination_first_seen");
        result["details"]["novelty"]["destination"] = json!("example.invalid:443");
        result["details"]["novelty"]["route"] = json!("direct");
    }
    result
}

pub(super) fn correlation_rows() -> Vec<Value> {
    let hash = format!("sha256:{}", "a".repeat(64));
    let mut source = indicator("C0");
    source["host"] = json!("source.invalid");
    source["request_id"] = json!("F0");
    source["details"]["sensor"] = json!("prompt-injection.v1");
    source["details"]["indicator_type"] = json!("prompt_instruction_override");
    source["details"]["direction"] = json!("server_to_client");
    source["details"]["evidence_hash"] = json!(hash);
    let mut exposure = indicator("C1");
    exposure["request_id"] = json!("F1");
    exposure["details"]["sensor"] = json!("prompt-injection.v1");
    exposure["details"]["indicator_type"] = json!("prompt_injection_exposure");
    exposure["details"]["rule"] = json!("prompt.source_text_overlap.v1");
    exposure["details"]["direction"] = json!("client_to_server");
    exposure["details"]["source"] = json!({"request_id":"F0","connection_id":"C0",
        "host":"source.invalid","evidence_hash":hash,"matched_fingerprints":8,"source_fingerprints":12});
    let mut rows = vec![
        connection("C0", "source-client"),
        upstream("S0", "source-server", "C0"),
        connection("C1", "model-client"),
        upstream("S1", "model-server", "C1"),
        source,
        flow("F0", "C0", "S0"),
        flow("F1", "C1", "S1"),
        first_observation(true, "C0", "source-client"),
        first_observation(false, "S0", "source-server"),
        first_observation(true, "C1", "model-client"),
        first_observation(false, "S1", "model-server"),
        exposure,
    ];
    for row in &mut rows {
        row["details"]["attribution"] = json!({"evidence_owner":"alice",
            "trusted_transport_identity":"alice","attribution_status":"resolved"});
        if row["event"] == "network.connection" {
            row["ts"] = json!("2026-01-01T00:00:00Z");
            row["details"]["started_at"] = row["ts"].clone();
        } else if row["details"].get("novelty").is_some() {
            row["ts"] = json!("2026-01-01T00:00:00Z");
        }
    }
    rows
}

pub(super) fn only_correlation(result: &Value) -> &Value {
    let correlations = result["correlations"].as_array().unwrap();
    assert_eq!(correlations.len(), 1, "{result}");
    &correlations[0]
}

fn assert_originals(result: &Value, rows: &[Value]) {
    for entry in result["records"].as_array().unwrap() {
        assert_eq!(
            entry["record"],
            rows[entry["line"].as_u64().unwrap() as usize - 1]
        );
    }
}

#[tokio::test]
async fn correlation_labels_source_and_model_connections_without_lifecycle_combinations() {
    let root = tempfile::tempdir().unwrap();
    configure(root.path());
    for shared in [false, true] {
        let mut rows = correlation_rows();
        if shared {
            for row in &mut rows {
                for field in [
                    "connection_id",
                    "client_connection_id",
                    "server_connection_id",
                ] {
                    if row["details"][field] == "C1" {
                        row["details"][field] = json!("C0");
                    }
                    if row["details"][field] == "S1" {
                        row["details"][field] = json!("S0");
                    }
                }
                for (old, new) in [("C1", "C0"), ("S1", "S0")] {
                    if row["details"]["novelty"]["current"]["connection_id"] == old {
                        row["details"]["novelty"]["current"]["connection_id"] = json!(new);
                    }
                }
            }
        }
        // Later snapshots, not additional request/novelty combinations.
        for i in 0..4 {
            let mut lifecycle = rows[i].clone();
            lifecycle["event_id"] = json!(format!("later-{i}"));
            lifecycle["details"]["state"] = json!("updated");
            rows.push(lifecycle);
        }
        write_rows(root.path(), &rows);
        let before = fs::read(root.path().join("audit.jsonl")).unwrap();
        for (kind, id) in [
            ("request", "F1"),
            ("connection", if shared { "C0" } else { "C1" }),
        ] {
            let result = success(root.path(), &pivot_args(kind, id)).await;
            let correlation = only_correlation(&result);
            assert_eq!(correlation["status"], "linked", "{correlation}");
            assert_eq!(correlation["source"]["record_lines"], json!([5]));
            for (side, flow_line) in [("source_transport", 6), ("model_transport", 7)] {
                assert_eq!(correlation[side]["flow_lines"], json!([flow_line]));
                let novelty = correlation[side]["novelty"].as_array().unwrap();
                assert_eq!(novelty.len(), if shared { 4 } else { 2 });
                for entry in novelty {
                    assert_eq!(entry["status"], "available");
                    assert!(
                        entry["reason"]
                            .as_str()
                            .unwrap()
                            .contains("connection-wide")
                    );
                    let expected = if entry["connection_role"] == "client" {
                        correlation[side]["client_connection_id"].clone()
                    } else {
                        correlation[side]["server_connection_id"].clone()
                    };
                    assert_eq!(entry["connection_id"], expected);
                    assert!(
                        entry["support"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .all(|link| link["record_lines"].as_array().unwrap().len() == 1)
                    );
                }
            }
            assert_originals(&result, &rows);
        }
        let args = pivot_args("request", "F1");
        let output = cli(root.path(), &args[..args.len() - 1]).await;
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        for expected in [
            "Prompt exposure correlation",
            "source_transport",
            "model_transport",
            "connection-wide",
            "malicious intent",
            "model receipt",
        ] {
            assert!(text.contains(expected), "{text}");
        }
        assert_eq!(fs::read(root.path().join("audit.jsonl")).unwrap(), before);
    }
}

#[tokio::test]
async fn generated_sparse_controls_require_exact_source_flows_events_and_trusted_agent() {
    let root = tempfile::tempdir().unwrap();
    configure(root.path());
    // Independent availability oracle over all 64 combinations; physical order
    // varies and timestamps deliberately do not describe temporal nearness.
    for mask in 0..64u64 {
        let mut rows = correlation_rows();
        if mask & 1 != 0 {
            rows[4]["details"]["evidence_hash"] = json!(format!("sha256:{}", "b".repeat(64)));
        }
        if mask & 2 != 0 {
            rows[5]["request_id"] = json!("other-source-request");
        }
        if mask & 4 != 0 {
            rows[6]["request_id"] = json!("other-model-request");
        }
        if mask & 8 != 0 {
            rows[0]["event_id"] = json!("unreferenced-source-event");
        }
        if mask & 16 != 0 {
            rows[3]["event_id"] = json!("unreferenced-model-event");
        }
        if mask & 32 != 0 {
            rows[11]["details"]["attribution"]["attribution_status"] = json!("unavailable");
        }
        let mut random = mask + 1;
        for i in (1..rows.len()).rev() {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            rows.swap(i, random as usize % (i + 1));
        }
        write_rows(root.path(), &rows);
        let result = success(root.path(), &pivot_args("request", "F1")).await;
        let correlation = only_correlation(&result);
        assert_eq!(
            correlation["status"],
            if mask == 0 {
                "linked"
            } else if mask & 32 != 0 {
                "unavailable"
            } else {
                "partial"
            },
            "mask={mask}: {correlation}"
        );
        assert_eq!(
            correlation["source"]["status"],
            if mask & 33 == 0 {
                "available"
            } else {
                "unavailable"
            }
        );
        assert_eq!(
            correlation["source_transport"]["status"],
            if mask & 35 == 0 {
                "available"
            } else {
                "unavailable"
            }
        );
        assert_eq!(
            correlation["model_transport"]["status"],
            if mask & 36 == 0 {
                "available"
            } else {
                "unavailable"
            }
        );
        assert_originals(&result, &rows);
    }
    for (pointer, value) in [
        ("/request_id", "other-request"),
        ("/details/connection_id", "other-client"),
        ("/details/direction", "client_to_server"),
        ("/host", "other.invalid"),
        ("/details/sensor", "other-sensor"),
        ("/details/instance_id", "I2"),
        ("/details/runtime_id", "R2"),
        ("/agent", "bob"),
        ("/details/attribution/trusted_transport_identity", "bob"),
    ] {
        let mut rows = correlation_rows();
        *rows[4].pointer_mut(pointer).unwrap() = json!(value);
        write_rows(root.path(), &rows);
        // With no --agent filter, matching local IDs must still not cross agents.
        let args = [
            "logs",
            "request",
            "F1",
            "--instance",
            "I1",
            "--runtime",
            "R1",
            "--json",
        ];
        let result = success(root.path(), &args).await;
        let correlation = only_correlation(&result);
        assert_eq!(
            correlation["source"]["status"], "unavailable",
            "{pointer}: {correlation}"
        );
        assert_eq!(correlation["source_transport"]["novelty"], json!([]));
        if pointer == "/agent" {
            assert!(
                result["links"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(
                        |link| link["field"] == "details.source" && link["status"] == "unavailable"
                    )
            );
        }
    }
}

#[tokio::test]
async fn paired_and_previous_observations_and_conflicting_flow_owners_require_real_support() {
    let root = tempfile::tempdir().unwrap();
    configure(root.path());
    for mode in 0..7 {
        let mut rows = correlation_rows();
        // Pairing needs both exact events on this flow's client and server.
        rows[10]["details"]["indicator_type"] = json!("tls_client_destination_novelty");
        rows[10]["details"]["novelty"]["client"] = rows[9]["details"]["novelty"]["current"].clone();
        match mode {
            1 => {
                rows[10]["details"]["novelty"]["client"]["event_id"] = json!("missing-client-event")
            }
            2 => {
                rows[10]["details"]["novelty"]["client"] =
                    rows[7]["details"]["novelty"]["current"].clone()
            }
            3 => {
                // A complete current fingerprint cannot replace an absent
                // previous observation named by the change indicator.
                let mut previous = rows[7]["details"]["novelty"]["current"].clone();
                previous["event_id"] = json!("missing-previous-event");
                previous["client_fingerprint"]["ja3"] = json!("b".repeat(32));
                rows[9]["details"]["novelty"]["previous"] = previous;
            }
            4 => {
                let mut conflicting = flow("F1", "C1", "another-upstream");
                conflicting["details"]["attribution"] = rows[6]["details"]["attribution"].clone();
                rows.push(conflicting);
            }
            5 => rows[3]["details"]["client_connection_id"] = json!("C0"),
            6 => {
                rows[0]["details"]
                    .as_object_mut()
                    .unwrap()
                    .remove("attribution");
            }
            _ => {}
        }
        write_rows(root.path(), &rows);
        let result = success(root.path(), &pivot_args("request", "F1")).await;
        let correlation = only_correlation(&result);
        assert_eq!(
            correlation["status"],
            if mode == 0 { "linked" } else { "partial" },
            "mode={mode}: {correlation}"
        );
        if mode == 4 {
            assert_eq!(correlation["model_transport"]["status"], "unavailable");
            assert_eq!(correlation["model_transport"]["novelty"], json!([]));
        }
        if (1..=3).contains(&mode) {
            assert!(
                correlation["model_transport"]["novelty"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|entry| entry["status"] == "unavailable")
            );
        }
        if mode == 6 {
            assert_eq!(
                correlation["source_transport"]["client_record_lines"],
                json!([])
            );
            assert_eq!(correlation["source_transport"]["status"], "partial");
        }
    }
    let mut rows = correlation_rows();
    let mut other = first_observation(true, "other-client", "other-event");
    other["details"]["novelty"]["current"]["client_fingerprint"]["ja3"] = json!("b".repeat(32));
    other["details"]["novelty"]["previous"] = rows[9]["details"]["novelty"]["current"].clone();
    other["details"]["attribution"] = rows[9]["details"]["attribution"].clone();
    rows.push(other);
    write_rows(root.path(), &rows);
    let result = success(root.path(), &pivot_args("connection", "C1")).await;
    let correlation = only_correlation(&result);
    assert_eq!(correlation["status"], "linked");
    assert!(
        correlation["model_transport"]["novelty"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["connection_id"] != "other-client"),
        "A previous observation alone must not establish a current connection relationship"
    );
}

#[tokio::test]
async fn windows_namespace_and_missing_evidence_keep_exposure_and_search_accounting() {
    let root = tempfile::tempdir().unwrap();
    configure(root.path());
    let baseline = correlation_rows();
    let mut rows = baseline[..11].to_vec();
    for i in 0..120 {
        let mut noise = connection(&format!("noise-{i}"), &format!("noise-event-{i}"));
        if i % 2 == 0 {
            noise["agent"] = json!("bob");
        }
        rows.push(noise);
        let mut foreign = baseline[4].clone();
        foreign["details"]["runtime_id"] = json!("another-runtime");
        rows.push(foreign);
    }
    rows.push(baseline[11].clone());
    write_rows(root.path(), &rows);
    let before = fs::read(root.path().join("audit.jsonl")).unwrap();
    let result = success(root.path(), &pivot_args("request", "F1")).await;
    assert_eq!(only_correlation(&result)["status"], "partial");
    assert_eq!(only_correlation(&result)["source"]["status"], "unavailable");
    assert_eq!(result["search"]["lines_read"], rows.len());
    assert_eq!(result["search"]["agent_rows"], rows.len() - 60);
    assert_eq!(result["search"]["retained_rows"], 100);
    assert_eq!(result["search"]["omitted_rows"], rows.len() - 160);
    let mut args = pivot_args("request", "F1");
    args.extend(["--lines", "1000"]);
    let result = success(root.path(), &args).await;
    assert_eq!(only_correlation(&result)["status"], "linked");
    assert_originals(&result, &rows);
    assert_eq!(fs::read(root.path().join("audit.jsonl")).unwrap(), before);
    // All support absent is still a retained exposure, not a clean result.
    write_rows(root.path(), &baseline[11..]);
    let result = success(root.path(), &args).await;
    assert_eq!(only_correlation(&result)["status"], "partial");
    assert_eq!(only_correlation(&result)["novelty_status"], "unavailable");
    assert_eq!(result["records"].as_array().unwrap().len(), 1);
}
