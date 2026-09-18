use super::*;

use crate::Proxy;
use serde_json::json;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TOKEN: &str = "operator-audit-submit-failure";
const POLICY: &str = r#"
budget = 10

[[permissions]]
action = "network:request"
resource = "*"
effect = "allow"
"#;

#[tokio::test]
async fn synchronous_audit_submission_failure_commits_mutations_then_closes_connection() {
    for mutation in ["baseline", "mode", "host"] {
        let directory = TempDir::new().unwrap();
        let config = config(directory.path());
        let proxy = Proxy::start(config.clone()).await.unwrap();
        let port = proxy.admin.as_ref().unwrap().address().port();

        // The runtime owns this writer. Poisoning its mutex makes the real
        // admin listener's Writer::emit return a synchronous submission error.
        proxy.runtime.read().unwrap().audit.poison_for_test();

        let (path, body) = match mutation {
            "baseline" => (
                "/admin/policy/baseline",
                br#"{"policy":{"budget":17,"permissions":[{"action":"network:request","resource":"replacement.example","effect":"allow"}]}}"#.as_slice(),
            ),
            "mode" => ("/plugins/network-guard/mode", br#"{"mode":"warn"}"#.as_slice()),
            "host" => (
                "/admin/policy/host/allow",
                br#"{"host":"sync-failure.example","rate":5}"#.as_slice(),
            ),
            _ => unreachable!(),
        };
        let method = if matches!(mutation, "baseline" | "mode") {
            "PUT"
        } else {
            "POST"
        };
        let response = raw_admin_request(port, method, path, body).await;

        // admin_listener propagates a synchronous submission error. Hyper
        // closes this request's connection without inventing a response.
        assert!(
            response.is_empty(),
            "{mutation} submission error produced an HTTP response: {:?}",
            String::from_utf8_lossy(&response)
        );

        let policy_path = config.policy_file.as_ref().unwrap();
        match mutation {
            "baseline" => {
                let source = std::fs::read_to_string(policy_path).unwrap();
                let document: toml_edit::DocumentMut = source.parse().unwrap();
                assert_eq!(document["budget"].as_integer(), Some(17));
                let permissions = document["permissions"].as_array().unwrap();
                assert_eq!(permissions.len(), 1);
                let permission = permissions.get(0).unwrap().as_inline_table().unwrap();
                assert_eq!(
                    permission.get("action").and_then(toml_edit::Value::as_str),
                    Some("network:request")
                );
                assert_eq!(
                    permission
                        .get("resource")
                        .and_then(toml_edit::Value::as_str),
                    Some("replacement.example")
                );
                assert_eq!(
                    permission.get("effect").and_then(toml_edit::Value::as_str),
                    Some("allow")
                );
                assert!(!source.contains("resource = \"*\""));
            }
            "mode" => assert_eq!(
                proxy.runtime.read().unwrap().operator_modes.network_block(),
                false,
                "mode mutation was rolled back"
            ),
            "host" => assert!(
                std::fs::read_to_string(policy_path)
                    .unwrap()
                    .contains("sync-failure.example"),
                "host write was rolled back"
            ),
            _ => unreachable!(),
        }
        proxy.shutdown().await;
    }
}

fn config(directory: &Path) -> Config {
    std::fs::write(directory.join("policy.toml"), POLICY).unwrap();
    std::fs::write(directory.join("operator-token"), TOKEN).unwrap();
    serde_json::from_value(json!({
        "listeners": [],
        "policy_file": directory.join("policy.toml"),
        "data_dir": directory.join("data"),
        "agent_api_enabled": false,
        "admin_port": 0,
        "admin_api_token_file": directory.join("operator-token"),
        "readiness_file": directory.join("ready.json"),
        "flow_store_enabled": false,
        "audit_log_path": directory.join("audit.jsonl"),
        "event_log": directory.join("events.jsonl")
    }))
    .unwrap()
}

async fn raw_admin_request(port: u16, method: &str, path: &str, body: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Authorization: Bearer {TOKEN}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}
