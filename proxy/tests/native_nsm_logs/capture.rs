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
    let limited = view(
        root,
        flow,
        path,
        "connection",
        connection,
        &["--file", window_audit.to_str().unwrap(), "--lines", "1"],
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
