use super::*;

pub(super) fn configure(config: &mut Config, root: &Path) -> std::path::PathBuf {
    let path = root.join("capture.pcap");
    let mut settings = safeyolo_proxy::native_config::Settings::default();
    settings.packet_capture.file = Some(path.clone());
    settings.packet_capture.payload_layers =
        vec![safeyolo_proxy::observations::Layer::TransportStream];
    config.native_settings = Some(settings);
    config.native_config_dir = Some(root.to_owned());
    let data = config.data_dir.as_ref().unwrap();
    fs::create_dir_all(data).unwrap();
    fs::write(
        data.join("instance_id"),
        "sy-0123456789abcdef0123456789abcdef",
    )
    .unwrap();
    path
}

// Keep actual producer packets, changing only selected metadata for negative
// controls. These files are test inputs, never measurements of network packets.
fn rewrite(bytes: &[u8], mut change: impl FnMut(&mut Value)) -> Vec<u8> {
    let mut output = bytes[..24].to_vec();
    let mut at = 24;
    while at < bytes.len() {
        let length = u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap()) as usize;
        let mut header = bytes[at..at + 16].to_vec();
        let mut frame = bytes[at + 16..at + 16 + length].to_vec();
        if frame[23] == 17 {
            let prefix = b"SAFEYOLO-PCAP-COMPAT/1\n";
            let mut metadata: Value =
                serde_json::from_slice(frame[42..].strip_prefix(prefix).unwrap()).unwrap();
            change(&mut metadata);
            frame.truncate(42);
            frame.extend(prefix);
            frame.extend(serde_json::to_vec(&metadata).unwrap());
            let length = frame.len();
            header[8..12].copy_from_slice(&(length as u32).to_le_bytes());
            header[12..16].copy_from_slice(&(length as u32).to_le_bytes());
            frame[16..18].copy_from_slice(&((length - 14) as u16).to_be_bytes());
            frame[38..40].copy_from_slice(&((length - 34) as u16).to_be_bytes());
        }
        output.extend(header);
        output.extend(frame);
        at += 16 + length;
    }
    output
}

// Decode the encoder's canonical metadata directly, independently of the pivot
// reader and its summaries. Payload packets are not used for measurements.
fn metadata(bytes: &[u8]) -> Vec<Value> {
    let mut rows = Vec::new();
    let mut offset = 24;
    let mut packet = 1;
    while offset < bytes.len() {
        let length =
            u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap()) as usize;
        let frame = &bytes[offset + 16..offset + 16 + length];
        if frame[23] == 17 {
            let record: Value = serde_json::from_slice(
                frame[42..]
                    .strip_prefix(b"SAFEYOLO-PCAP-COMPAT/1\n")
                    .unwrap(),
            )
            .unwrap();
            rows.push(json!({"packet":packet,"byte_offset":offset,"metadata":record}));
        }
        offset += 16 + length;
        packet += 1;
    }
    rows
}

pub(super) async fn assert_exposure_views(root: &Path, exposure: &Value, path: &Path) {
    let audit = fs::read(root.join("audit.jsonl")).unwrap();
    let bytes = fs::read(path).unwrap();
    let canonical = metadata(&bytes);
    assert!(
        canonical
            .iter()
            .filter(|r| r["metadata"]["type"] == "observation")
            .all(|r| r["metadata"]["observation"]["captured_length"] == 0)
    );
    assert!(
        !bytes
            .windows(b"amber lighthouse".len())
            .any(|w| w == b"amber lighthouse")
    );
    let offline = root.join("offline-exposure-no-config");
    let audit_path = root.join("audit.jsonl");
    let request = exposure["request_id"].as_str().unwrap();
    let extra = ["--file", audit_path.to_str().unwrap(), "--lines", "1000"];
    let result = view(&offline, exposure, path, "request", request, &extra).await;
    let correlation = &result["correlations"][0];
    assert_eq!(correlation["status"], "linked");
    let mut intervals = 0;
    for side in ["source_transport", "model_transport"] {
        let transport = &correlation[side];
        let summary = &transport["behaviour"];
        assert_eq!(summary["status"], "available", "{summary}");
        let groups = summary["groups"].as_array().unwrap();
        assert!(!groups.is_empty());
        let expected_chunks = canonical
            .iter()
            .filter(|row| {
                let o = &row["metadata"]["observation"];
                row["metadata"]["type"] == "observation"
                    && o["state"] == "chunk"
                    && o["layer"] != "wire_packet"
                    && ["client_connection_id", "server_connection_id"]
                        .iter()
                        .any(|field| o["connection_id"] == transport[field])
            })
            .count();
        assert_eq!(
            groups
                .iter()
                .map(|g| g["retained_chunks"].as_u64().unwrap())
                .sum::<u64>(),
            expected_chunks as u64
        );
        for field in ["client_connection_id", "server_connection_id"] {
            assert!(
                groups
                    .iter()
                    .any(|g| g["connection_id"] == transport[field]),
                "{transport}"
            );
        }
        for group in groups {
            let expected: Vec<_> = canonical
                .iter()
                .filter(|row| {
                    let o = &row["metadata"]["observation"];
                    row["metadata"]["type"] == "observation"
                        && o["state"] == "chunk"
                        && ["connection_id", "point", "layer", "direction"]
                            .iter()
                            .all(|key| o[key] == group[key])
                })
                .collect();
            assert_eq!(group["retained_chunks"], expected.len());
            let lengths: Vec<_> = expected
                .iter()
                .map(|r| {
                    r["metadata"]["observation"]["observed_length"]
                        .as_u64()
                        .unwrap()
                })
                .collect();
            assert_eq!(group["observed_bytes"], lengths.iter().sum::<u64>());
            assert_eq!(group["min_chunk_bytes"], *lengths.iter().min().unwrap());
            assert_eq!(group["max_chunk_bytes"], *lengths.iter().max().unwrap());
            let gaps: Vec<_> = expected
                .windows(2)
                .map(|pair| {
                    pair[1]["metadata"]["observation"]["timestamp"]["monotonic_ns"]
                        .as_u64()
                        .unwrap()
                        - pair[0]["metadata"]["observation"]["timestamp"]["monotonic_ns"]
                            .as_u64()
                            .unwrap()
                })
                .collect();
            let timing = &group["retained_inter_chunk_intervals_ns"];
            assert_eq!(timing["count"], gaps.len());
            assert_eq!(timing["sum"], gaps.iter().sum::<u64>());
            assert_eq!(timing["min"], json!(gaps.iter().min()));
            assert_eq!(timing["max"], json!(gaps.iter().max()));
            intervals += gaps.len();
            let chunks = group["chunks"].as_array().unwrap();
            assert_eq!(chunks.len(), expected.len());
            for (index, (chunk, row)) in chunks.iter().zip(&expected).enumerate() {
                assert_eq!(chunk["packet"], row["packet"]);
                assert_eq!(chunk["byte_offset"], row["byte_offset"]);
                let o = &row["metadata"]["observation"];
                for (output, input) in [
                    ("observation_id", "id"),
                    ("stream_offset", "stream_offset"),
                    ("observed_length", "observed_length"),
                    ("timestamp", "timestamp"),
                    ("timestamp_resolution", "timestamp_resolution"),
                ] {
                    assert_eq!(chunk[output], o[input]);
                }
                assert_eq!(
                    chunk["interval_from_previous_ns"],
                    json!(index.checked_sub(1).map(|i| gaps[i]))
                );
                assert!(!chunk["audit_record_lines"].as_array().unwrap().is_empty());
                for line in chunk["audit_record_lines"].as_array().unwrap() {
                    let record = result["records"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|r| r["line"] == *line)
                        .unwrap();
                    assert_eq!(line["input"], 1);
                    assert_eq!(record["record"]["agent"], "alice");
                    assert!(
                        record["record"]["details"]["connection_id"] == group["connection_id"]
                            || record["record"]["details"]["client_connection_id"]
                                == group["connection_id"]
                            || record["record"]["details"]["server_connection_id"]
                                == group["connection_id"]
                    );
                }
            }
        }
    }
    assert!(
        intervals > 0,
        "split live writes must exercise retained chunk intervals"
    );
    assert!(!result.to_string().contains("amber lighthouse"));
    assert!(
        !result
            .to_string()
            .contains("synthetic-correlation-credential")
    );
    assert!(!offline.exists());

    let without_source = root.join("without-source.jsonl");
    let source_rows = std::str::from_utf8(&audit)
        .unwrap()
        .lines()
        .filter(|line| {
            let row: Value = serde_json::from_str(line).unwrap();
            !(row["event"] == "security.indicator"
                && row["request_id"] == exposure["details"]["source"]["request_id"])
        })
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    fs::write(&without_source, source_rows).unwrap();
    let absent_source = view(
        &offline,
        exposure,
        path,
        "request",
        request,
        &[
            "--file",
            without_source.to_str().unwrap(),
            "--lines",
            "1000",
        ],
    )
    .await;
    assert_eq!(
        absent_source["correlations"][0]["source_transport"]["behaviour"]["status"],
        "unavailable"
    );
    assert_eq!(
        absent_source["correlations"][0]["model_transport"]["behaviour"]["status"],
        "available"
    );

    let altered = root.join("exposure-selected.pcap");
    for field in ["instance", "runtime", "agent", "attribution", "connection"] {
        fs::write(
            &altered,
            rewrite(&bytes, |m| {
                if m["type"] == "session" && ["instance", "runtime"].contains(&field) {
                    m["session"][format!("{field}_id")] = json!("other");
                }
                if m["type"] != "observation" {
                    return;
                }
                match field {
                    "instance" | "runtime" => {
                        m["source"][format!("{field}_id")] = json!("other");
                        m["observation"]["id"][format!("{field}_id")] = json!("other");
                        m["observation"]["input_span"] = Value::Null;
                        m["observation"]["parent_observation"] = Value::Null;
                    }
                    "agent" => m["observation"]["agent"] = json!("mallory"),
                    "attribution" => {
                        m["observation"]["attribution"]["trusted_transport_identity"] =
                            json!("mallory")
                    }
                    "connection" => {
                        m["source"]["connection_id"] = json!("other");
                        m["observation"]["connection_id"] = json!("other");
                    }
                    _ => unreachable!(),
                }
            }),
        )
        .unwrap();
        let changed = view(&offline, exposure, &altered, "request", request, &extra).await;
        assert_eq!(
            changed["capture"]["scan"]["read_to_eof"], true,
            "{field}: {changed}"
        );
        for side in ["source_transport", "model_transport"] {
            assert_eq!(
                changed["correlations"][0][side]["behaviour"]["status"], "unavailable",
                "{field}: {changed}"
            );
        }
    }
    // Request ID changes do not erase connection-scoped chunks. Shared input
    // remains descriptive context even when a request cannot own it exclusively.
    fs::write(
        &altered,
        rewrite(&bytes, |m| {
            if m["type"] == "observation" && !m["observation"]["request_id"].is_null() {
                m["observation"]["request_id"] = json!("another-request");
            }
        }),
    )
    .unwrap();
    let shared = view(&offline, exposure, &altered, "request", request, &extra).await;
    assert_eq!(shared["capture"]["status"], "unavailable");
    for side in ["source_transport", "model_transport"] {
        let mut actual = shared["correlations"][0][side]["behaviour"].clone();
        let mut expected = correlation[side]["behaviour"].clone();
        // Rewriting metadata changes later byte offsets, while connection
        // measurements, observation IDs and packet numbers stay the same.
        for summary in [&mut actual, &mut expected] {
            for group in summary["groups"].as_array_mut().unwrap() {
                for chunk in group["chunks"].as_array_mut().unwrap() {
                    chunk.as_object_mut().unwrap().remove("byte_offset");
                }
            }
        }
        assert_eq!(actual, expected);
    }
    // Clock resolution describes precision. Same-runtime monotonic intervals
    // survive unknown resolution and wall corrections, as in the live metrics.
    for clock in [
        "unknown_resolution",
        "wall_adjustment",
        "reversed_monotonic",
    ] {
        fs::write(
            &altered,
            rewrite(&bytes, |m| {
                if m["type"] == "observation" {
                    let sequence = m["observation"]["id"]["sequence"].as_u64().unwrap();
                    match clock {
                        "unknown_resolution" => {
                            m["observation"]["timestamp_resolution"]["monotonic_ns"] = Value::Null
                        }
                        "wall_adjustment" => {
                            m["observation"]["timestamp"]["wall_unix_ns"] =
                                json!(-i128::from(sequence))
                        }
                        _ => {
                            m["observation"]["timestamp"]["monotonic_ns"] =
                                json!(u64::MAX - sequence)
                        }
                    }
                }
            }),
        )
        .unwrap();
        let changed = view(&offline, exposure, &altered, "request", request, &extra).await;
        let mut unavailable = 0;
        for side in ["source_transport", "model_transport"] {
            for (group, original) in changed["correlations"][0][side]["behaviour"]["groups"]
                .as_array()
                .unwrap()
                .iter()
                .zip(correlation[side]["behaviour"]["groups"].as_array().unwrap())
            {
                let timing = &group["retained_inter_chunk_intervals_ns"];
                if clock == "reversed_monotonic" {
                    assert_eq!(timing["count"], 0);
                    unavailable += timing["unavailable"].as_u64().unwrap();
                } else {
                    assert_eq!(*timing, original["retained_inter_chunk_intervals_ns"]);
                    if clock == "unknown_resolution" {
                        assert!(
                            group["chunks"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .all(|c| c["timestamp_resolution"]["monotonic_ns"].is_null())
                        );
                    }
                }
            }
        }
        if clock == "reversed_monotonic" {
            assert!(unavailable > 0);
        }
    }
    for kind in ["canonical", "sink"] {
        let mut inserted = false;
        let session = &canonical[0]["metadata"]["session"];
        fs::write(&altered, rewrite(&bytes, |m| {
            if !inserted && m["type"] == "observation" {
                let sequence = m["observation"]["id"]["sequence"].as_u64().unwrap();
                *m = json!({"instance_id":session["instance_id"],"runtime_id":session["runtime_id"],"first_sequence":sequence,"last_sequence":sequence,"count":1,"reason":"fixture_loss"});
                if kind == "sink" {
                    m["type"] = json!("sink_gap");
                    m["sink_session_id"] = session["sink_session_id"].clone();
                } else { m["record"] = json!("gap"); }
                inserted = true;
            }
        })).unwrap();
        let changed = view(&offline, exposure, &altered, "request", request, &extra).await;
        assert_eq!(
            changed["capture"]["loss"][0]["connection_request_attribution"],
            "unavailable"
        );
        assert_eq!(changed["capture"]["loss"][0]["scope"], "runtime");
        for side in ["source_transport", "model_transport"] {
            assert_eq!(
                changed["correlations"][0][side]["behaviour"]["status"],
                "partial"
            );
        }
    }
    fs::write(&altered, &bytes[..bytes.len() - 1]).unwrap();
    let truncated = view(&offline, exposure, &altered, "request", request, &extra).await;
    assert_eq!(truncated["capture"]["scan"]["status"], "partial");
    assert_eq!(
        truncated["correlations"][0]["source_transport"]["behaviour"]["status"],
        "partial"
    );
    fs::remove_file(&altered).unwrap();
    let missing = view(&offline, exposure, &altered, "request", request, &extra).await;
    assert_eq!(
        missing["correlations"][0]["source_transport"]["behaviour"]["status"],
        "unavailable"
    );
    // Each selected audit file retains its anchor with --lines=1. The capture
    // has one shared observation budget, so the same query demonstrates loss
    // of retained context without removing the audit correlation itself.
    let audit_rows: Vec<_> = std::str::from_utf8(&audit).unwrap().lines().collect();
    let files: Vec<_> = audit_rows
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let file = root.join(format!("window-{index}.jsonl"));
            fs::write(&file, format!("{row}\n")).unwrap();
            file
        })
        .collect();
    let mut window_args = vec!["--lines", "1"];
    for file in &files {
        window_args.extend(["--file", file.to_str().unwrap()]);
    }
    let limited = view(&offline, exposure, path, "request", request, &window_args).await;
    assert_eq!(limited["correlations"].as_array().unwrap().len(), 1);
    assert!(
        limited["capture"]["omitted_connection_observations"]
            .as_u64()
            .unwrap()
            > 0
    );
    for side in ["source_transport", "model_transport"] {
        assert_ne!(
            limited["correlations"][0][side]["behaviour"]["status"],
            "available"
        );
    }
    assert_eq!(fs::read(path).unwrap(), bytes);
    assert_eq!(fs::read(audit_path).unwrap(), audit);
}

async fn view(
    root: &Path,
    flow: &Value,
    path: &Path,
    kind: &str,
    id: &str,
    extra: &[&str],
) -> Value {
    let mut args = vec![
        "logs",
        kind,
        id,
        "--instance",
        flow["details"]["instance_id"].as_str().unwrap(),
        "--runtime",
        flow["details"]["runtime_id"].as_str().unwrap(),
        "--agent",
        "alice",
        "--capture",
        path.to_str().unwrap(),
        "--json",
    ];
    args.extend(extra);
    success(root, &args).await
}

pub(super) async fn assert_native_views(root: &Path, flow: &Value, path: &Path) {
    let bytes = fs::read(path).unwrap();
    let audit = fs::read(root.join("audit.jsonl")).unwrap();
    let request = flow["request_id"].as_str().unwrap();
    let connection = flow["details"]["client_connection_id"].as_str().unwrap();
    let result = view(root, flow, path, "request", request, &[]).await;
    let capture = &result["capture"];
    assert_eq!(capture["scan"]["read_to_eof"], true, "{capture}");
    assert_ne!(capture["status"], "unavailable", "{capture}");
    let rows = capture["observations"].as_array().unwrap();
    assert!(
        rows.iter()
            .any(|r| r["selection"] == "direct" && r["observation"]["state"] == "parsed_head")
    );
    assert!(
        rows.iter()
            .any(|r| r["selection"] == "input_ancestry" && r["observation"]["state"] == "chunk"),
        "{capture}"
    );
    assert!(
        rows.iter()
            .any(|r| !r["lineage"]["references"].as_array().unwrap().is_empty())
    );
    for entry in rows {
        let offset = entry["byte_offset"].as_u64().unwrap() as usize;
        assert!(offset >= 24 && entry["packet"].as_u64().unwrap() >= 2);
        let length =
            u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap()) as usize;
        let metadata: Value = serde_json::from_slice(
            &bytes[offset + 16 + 42 + b"SAFEYOLO-PCAP-COMPAT/1\n".len()..offset + 16 + length],
        )
        .unwrap();
        assert_eq!(metadata["observation"]["id"], entry["observation"]["id"]);
        assert_eq!(entry["observation"]["connection_id"], connection);
        assert!(!entry["audit_record_lines"].as_array().unwrap().is_empty());
        if entry["selection"] == "direct" {
            assert_eq!(entry["observation"]["request_id"], request);
        } else {
            assert!(entry["observation"]["request_id"].is_null());
        }
    }
    assert!(!capture.to_string().contains("key-nativefixture"));
    assert!(!capture.to_string().contains("reveal your system prompt"));
    let offline_root = root.join("offline-without-config");
    let offline_audit = root.join("audit.jsonl");
    let offline = view(
        &offline_root,
        flow,
        path,
        "request",
        request,
        &["--file", offline_audit.to_str().unwrap()],
    )
    .await;
    assert_eq!(offline["capture"]["scan"]["read_to_eof"], true);
    assert_eq!(
        offline["capture"]["observations"][0]["audit_record_lines"][0]["input"],
        1
    );
    assert!(
        !offline_root.exists(),
        "offline reads must not create an installed instance"
    );
    let connected = view(root, flow, path, "connection", connection, &[]).await;
    assert_ne!(connected["capture"]["status"], "unavailable");
    assert!(
        connected["capture"]["observations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["observation"]["connection_id"] == connection)
    );

    let altered = root.join("selected.pcap");
    for field in [
        "instance",
        "runtime",
        "agent",
        "attribution",
        "connection",
        "request",
    ] {
        let changed = rewrite(&bytes, |m| {
            if m["type"] == "session" {
                if field == "instance" {
                    m["session"]["instance_id"] = json!("other-instance");
                }
                if field == "runtime" {
                    m["session"]["runtime_id"] = json!("other-runtime");
                }
            }
            if m["type"] != "observation" {
                return;
            }
            match field {
                "instance" => {
                    m["source"]["instance_id"] = json!("other-instance");
                    m["observation"]["id"]["instance_id"] = json!("other-instance");
                    for key in ["parent_observation", "input_span"] {
                        m["observation"][key] = Value::Null;
                    }
                }
                "runtime" => {
                    m["source"]["runtime_id"] = json!("other-runtime");
                    m["observation"]["id"]["runtime_id"] = json!("other-runtime");
                    for key in ["parent_observation", "input_span"] {
                        m["observation"][key] = Value::Null;
                    }
                }
                "agent" => {
                    m["observation"]["agent"] = json!("mallory");
                    for key in ["evidence_owner", "trusted_transport_identity"] {
                        m["observation"]["attribution"][key] = json!("mallory");
                    }
                    m["observation"]["attribution"]["provenance"]["uds_agent"] = json!("mallory");
                }
                "attribution" => {
                    m["observation"]["attribution"]["trusted_transport_identity"] = json!("mallory")
                }
                "connection" => {
                    m["source"]["connection_id"] = json!("other-connection");
                    m["observation"]["connection_id"] = json!("other-connection");
                }
                "request" if !m["observation"]["request_id"].is_null() => {
                    m["observation"]["request_id"] = json!("other-request")
                }
                _ => {}
            }
        });
        fs::write(&altered, changed).unwrap();
        let result = view(root, flow, &altered, "request", request, &[]).await;
        assert_eq!(
            result["capture"]["scan"]["read_to_eof"], true,
            "{field}: {result}"
        );
        assert_eq!(
            result["capture"]["status"], "unavailable",
            "{field}: {result}"
        );
        assert!(
            result["capture"]["observations"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{field}: {result}"
        );
    }
    let changed = rewrite(&bytes, |m| {
        if m["type"] == "observation" {
            m["observation"]["input_span"] = Value::Null;
            m["observation"]["parent_observation"] = Value::Null;
            m["observation"]["payload"] = json!("injected-content-canary");
        }
    });
    fs::write(&altered, changed).unwrap();
    let absent = view(root, flow, &altered, "request", request, &[]).await;
    assert_eq!(absent["capture"]["status"], "partial");
    assert!(
        absent["capture"]["observations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["selection"] == "direct" && r["lineage"]["status"] == "unavailable")
    );
    assert!(!absent.to_string().contains("injected-content-canary"));

    // Reuse a metadata datagram from the actual producer for a loss-only control.
    let gap = rewrite(&bytes, |m| {
        if m["type"] == "observation" {
            *m = json!({"record":"gap","instance_id":flow["details"]["instance_id"],"runtime_id":flow["details"]["runtime_id"],"first_sequence":100,"last_sequence":102,"count":3,"reason":"consumer_admission_unavailable"});
        }
    });
    fs::write(&altered, gap).unwrap();
    let lost = view(root, flow, &altered, "request", request, &[]).await;
    assert_eq!(lost["capture"]["status"], "unavailable");
    assert!(
        lost["capture"]["loss"]
            .as_array()
            .unwrap()
            .iter()
            .all(|g| g["scope"] == "runtime"
                && g["connection_request_attribution"] == "unavailable"
                && g["count"] == 3)
    );
    assert!(!lost["capture"]["loss"].as_array().unwrap().is_empty());

    let mut truncated = bytes.clone();
    truncated.pop();
    fs::write(&altered, truncated).unwrap();
    let truncated = view(root, flow, &altered, "request", request, &[]).await;
    assert_eq!(truncated["capture"]["scan"]["status"], "partial");
    assert_eq!(truncated["capture"]["status"], "partial");
    // Keep a real scope anchor inside the small audit window, so the independent
    // capture-window control cannot fail merely because audit selection omitted it.
    let scope = std::str::from_utf8(&audit)
        .unwrap()
        .lines()
        .find(|line| {
            let row: Value = serde_json::from_str(line).unwrap();
            row["event"] == "network.connection" && row["details"]["connection_id"] == connection
        })
        .unwrap();
    let window_audit = root.join("window.jsonl");
    fs::write(&window_audit, format!("{scope}\n")).unwrap();
    let window_flow = root.join("window-flow.jsonl");
    fs::write(&window_flow, format!("{flow}\n")).unwrap();
    let limited = view(
        root,
        flow,
        path,
        "connection",
        connection,
        &[
            "--file",
            window_audit.to_str().unwrap(),
            "--file",
            window_flow.to_str().unwrap(),
            "--lines",
            "1",
        ],
    )
    .await;
    assert_eq!(limited["capture"]["status"], "partial");
    assert_eq!(
        limited["capture"]["observations"].as_array().unwrap().len(),
        1
    );
    assert!(
        limited["capture"]["omitted_connection_observations"]
            .as_u64()
            .unwrap()
            > 0
    );
    let connection_observations = metadata(&bytes)
        .iter()
        .filter(|r| {
            r["metadata"]["type"] == "observation"
                && r["metadata"]["observation"]["connection_id"] == connection
        })
        .count();
    assert_eq!(
        limited["capture"]["omitted_connection_observations"],
        connection_observations - 1,
        "A connection query without exposure correlation keeps only that connection, even when its flow also names an upstream"
    );
    for bad in [vec![], b"not a capture".to_vec(), vec![0; 24]] {
        fs::write(&altered, bad).unwrap();
        let result = view(root, flow, &altered, "request", request, &[]).await;
        assert_eq!(result["capture"]["status"], "unavailable");
        assert!(
            result["capture"]["observations"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    for bad_field in ["source", "state", "length", "record_type", "lineage"] {
        let malformed = rewrite(&bytes, |m| {
            if m["type"] != "observation" {
                return;
            }
            match bad_field {
                "source" => m["source"]["connection_id"] = json!("contradicts-observation"),
                "state" => m["observation"]["state"] = json!("invented-state"),
                "length" => m["observation"]["captured_length"] = json!(-1),
                "record_type" => m["type"] = json!("unknown"),
                "lineage" => {
                    m["observation"]["parent_observation"] =
                        json!({"instance_id":"wrong","runtime_id":"wrong","sequence":0})
                }
                _ => unreachable!(),
            }
        });
        fs::write(&altered, malformed).unwrap();
        let result = view(root, flow, &altered, "request", request, &[]).await;
        assert_eq!(
            result["capture"]["status"], "unavailable",
            "{bad_field}: {result}"
        );
        assert_eq!(
            result["capture"]["scan"]["status"], "partial",
            "{bad_field}: {result}"
        );
        assert!(
            result["capture"]["observations"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    let missing = view(
        root,
        flow,
        &root.join("absent.pcap"),
        "request",
        request,
        &[],
    )
    .await;
    assert_eq!(missing["capture"]["status"], "unavailable");
    assert!(!missing["records"].as_array().unwrap().is_empty());
    let ordinary = cli(
        root,
        &[
            "logs",
            "request",
            request,
            "--instance",
            flow["details"]["instance_id"].as_str().unwrap(),
            "--runtime",
            flow["details"]["runtime_id"].as_str().unwrap(),
            "--capture",
            path.to_str().unwrap(),
        ],
    )
    .await;
    assert!(ordinary.status.success());
    assert!(String::from_utf8_lossy(&ordinary.stdout).contains("Selected capture metadata"));
    assert_eq!(fs::read(path).unwrap(), bytes);
    assert_eq!(fs::read(root.join("audit.jsonl")).unwrap(), audit);
}
