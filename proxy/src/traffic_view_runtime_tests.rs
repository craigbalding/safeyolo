//! Retention publication and live HTTP observations with owned fixture state.

use super::*;
use crate::websocket::{Event, Message, Reader, Writer};
use bytes::Bytes;
use flate2::read::ZlibDecoder;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use std::{io::Read, net::SocketAddr};
use traffic_view::RequestInfo;
use tungstenite::protocol::frame::{
    FrameHeader,
    coding::{Data, OpCode},
};

fn config(directory: &Path) -> Config {
    let policy = directory.join("policy.json");
    std::fs::write(&policy, "{}").unwrap();
    serde_json::from_value(json!({
        "listeners":[], "policy_file":policy, "data_dir":directory.join("data"), "flow_store_enabled":false,
        "audit_log_path":directory.join("audit.jsonl"),
        "event_log":directory.join("events.jsonl"),
        "readiness_file":directory.join("ready.json"),
    }))
    .unwrap()
}

#[test]
fn retention_defaults_are_source_soft_targets_and_zero_is_invalid() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    assert_eq!(config.flow_pruner_max, 5000);
    assert_eq!(config.flow_pruner_max_body_bytes, 1024 * 1024 * 1024);
    config.flow_pruner_max = 0;
    assert!(config.validate().is_err());
    config.flow_pruner_max = 1;
    config.flow_pruner_max_body_bytes = 0;
    assert!(config.validate().is_err());
}

#[tokio::test]
async fn accepted_reload_preserves_view_scope_and_filter_and_publishes_retention() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    config.flow_pruner_max = 3;
    let mut proxy = Proxy::start(config.clone()).await.unwrap();
    let initial = proxy.runtime.read().unwrap().traffic_view.clone();
    initial.set_scope(&json!({"agent":"alice"})).unwrap();
    initial.set_user_filter("  ~m GET  ").unwrap();
    for id in ["first", "second"] {
        let exchange = initial.begin(RequestInfo {
            id: id.into(),
            connection_id: "owned".into(),
            agent: Some("alice".into()),
            method: "GET".into(),
            url: "http://owned.invalid/".into(),
            headers: vec![],
            started: 1.,
        });
        exchange.finish(None);
    }
    assert_eq!(
        initial.flows().unwrap()["flows"].as_array().unwrap().len(),
        2
    );
    config.flow_pruner_max = 1;
    let mut failed = config.clone();
    failed.policy_file = Some(directory.path().join("missing-policy.json"));
    assert!(proxy.reload(failed).await.is_err());
    assert_eq!(initial.scope()["user_filter"], "  ~m GET  ");
    assert!(initial.detail("first").is_some());
    assert!(initial.detail("second").is_some());
    proxy.reload(config.clone()).await.unwrap();
    let current = proxy.runtime.read().unwrap().traffic_view.clone();
    assert!(Arc::ptr_eq(&initial, &current));
    assert_eq!(current.scope()["agent"], "alice");
    assert_eq!(current.scope()["user_filter"], "  ~m GET  ");
    assert!(current.detail("first").is_none());
    assert!(current.detail("second").is_some());
    proxy.shutdown().await;
    assert!(!config.readiness_file.exists());
}

#[tokio::test]
async fn ordinary_http_is_visible_while_pending_and_completes_across_reload() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use traffic_view::Side;

    tokio::time::timeout(Duration::from_secs(5), async {
        let directory = tempfile::tempdir().unwrap();
        let mut config = config(directory.path());
        std::fs::write(config.policy_file.as_ref().unwrap(),
            r#"{"permissions":[{"action":"network:request","resource":"*","effect":"allow"}]}"#).unwrap();
        // This fixture owns its loopback origin; private-address protection is
        // exercised elsewhere and is not the contract under test here.
        config.network_guard_enabled = false;
        let socket_path = directory.path().join("alice.sock");
        config.listeners.push(AgentListener {
            agent_id: "alice".into(), socket_path: socket_path.clone(), source_id: None,
        });
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = origin.local_addr().unwrap();
        let (request_seen, request_ready) = tokio::sync::oneshot::channel();
        let (release_response, response_ready) = tokio::sync::oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let mut received = Vec::new();
            loop {
                let mut block = [0; 1024];
                let size = stream.read(&mut block).await.unwrap();
                assert!(size > 0);
                received.extend_from_slice(&block[..size]);
                if let Some(end) = received.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                    && received.len() >= end + 8 {
                    assert_eq!(&received[end + 4..end + 8], b"body");
                    break;
                }
            }
            request_seen.send(()).unwrap();
            response_ready.await.unwrap();
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\ndone").await.unwrap();
        });
        let mut proxy = Proxy::start(config.clone()).await.unwrap();
        let view = proxy.runtime.read().unwrap().traffic_view.clone();
        assert!(proxy.runtime.read().unwrap().flow_recorder.store().is_none());
        let mut client = UnixStream::connect(&socket_path).await.unwrap();
        client.write_all(format!("POST http://{address}/owned?x=1&x=2 HTTP/1.1\r\nHost: {address}\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody").as_bytes()).await.unwrap();
        request_ready.await.unwrap();
        let flows = view.flows().unwrap();
        let rows = flows["flows"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        let id = rows[0]["id"].as_str().unwrap().to_owned();
        assert_eq!(rows[0]["agent"], "alice");
        assert_eq!(rows[0]["state"], "pending");
        let pending = view.detail(&id).unwrap();
        assert!(pending["metadata"].get("test_context").is_none());
        assert!(pending["request_completed"].as_f64().is_some());
        assert!(pending["response_head_observed"].is_null());
        assert!(pending["response_completed"].is_null());
        assert!(pending["ended"].is_null());
        let upstream = pending["upstream"].clone();
        assert!(!upstream["id"].as_str().unwrap().is_empty());
        assert_eq!(upstream["route"], "direct");
        assert_eq!(upstream["peer"], address.to_string());
        let connection_started = upstream["started"].as_f64().unwrap();
        let tcp_setup = upstream["tcp_setup"].as_f64().unwrap();
        assert!(connection_started <= tcp_setup);
        assert!(upstream["tls_setup"].is_null());
        assert_eq!(view.body(&id, Side::Request).unwrap()["data_base64"], STANDARD.encode(b"body"));
        view.set_scope(&json!({"agent":"alice"})).unwrap();
        config.flow_pruner_max = 2;
        proxy.reload(config.clone()).await.unwrap();
        assert!(Arc::ptr_eq(&view, &proxy.runtime.read().unwrap().traffic_view));
        release_response.send(()).unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        assert!(reply.starts_with(b"HTTP/1.1 200"));
        assert!(reply.ends_with(b"done"));
        origin_task.await.unwrap();
        let row = view.detail(&id).unwrap();
        assert_eq!(row["state"], "complete");
        assert_eq!(row["status"], 200);
        assert_eq!(row["upstream"], upstream);
        assert_eq!(row["request_completed"], pending["request_completed"]);
        let response_head = row["response_head_observed"].as_f64().unwrap();
        let response_completed = row["response_completed"].as_f64().unwrap();
        assert!(tcp_setup <= response_head);
        assert!(response_head <= response_completed);
        assert!(response_completed <= row["ended"].as_f64().unwrap());
        assert_eq!(view.body(&id, Side::Response).unwrap()["data_base64"], STANDARD.encode(b"done"));
        assert_eq!(view.scope()["agent"], "alice");
        proxy.shutdown().await;
        assert!(!socket_path.exists());
        assert!(!config.readiness_file.exists());
    }).await.expect("owned HTTP view fixture must finish");
}

async fn operator_http(
    address: SocketAddr,
    token: &str,
    method: Method,
    target: &str,
    body: &[u8],
) -> (StatusCode, hyper::HeaderMap, Bytes) {
    let stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let task = tokio::spawn(connection);
    let request = Request::builder()
        .method(method)
        .uri(target)
        .header("Host", "localhost")
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Length", body.len())
        .body(Full::new(Bytes::copy_from_slice(body)))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    drop(sender);
    let _ = task.await;
    (status, headers, body)
}

async fn owned_http_request(agent_socket: &Path, path: &str, response_body: &[u8]) -> Vec<u8> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin_address = origin.local_addr().unwrap();
    let path = path.to_owned();
    let origin_path = path.clone();
    let response_body = response_body.to_vec();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut block = [0; 1024];
            let size = stream.read(&mut block).await.unwrap();
            assert!(size > 0, "origin closed before receiving request");
            request.extend_from_slice(&block[..size]);
        }
        assert!(
            String::from_utf8_lossy(&request).starts_with(&format!("GET {origin_path} HTTP/1.1"))
        );
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n",
            response_body.len()
        );
        stream.write_all(head.as_bytes()).await.unwrap();
        stream.write_all(&response_body).await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let mut client = tokio::net::UnixStream::connect(agent_socket).await.unwrap();
    client
        .write_all(
            format!(
                "GET http://{origin_address}{path} HTTP/1.1\r\nHost: {origin_address}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    origin_task.await.unwrap();
    response
}

#[tokio::test]
async fn live_operator_inspector_enforces_configured_flow_limit() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let directory = tempfile::tempdir().unwrap();
        let mut config = config(directory.path());
        std::fs::write(
            config.policy_file.as_ref().unwrap(),
            r#"{"permissions":[{"action":"network:request","resource":"*","effect":"allow"}]}"#,
        )
        .unwrap();
        config.network_guard_enabled = false;
        config.flow_pruner_max = 1;
        let agent_socket = directory.path().join("alice.sock");
        config.listeners.push(AgentListener {
            agent_id: "alice".into(),
            socket_path: agent_socket.clone(),
            source_id: None,
        });
        let token = "live-retention-token";
        let token_path = directory.path().join("operator-token");
        std::fs::write(&token_path, token).unwrap();
        config.admin_port = Some(0);
        config.admin_api_token_file = Some(token_path);

        let proxy = Proxy::start(config.clone()).await.unwrap();
        let admin_address = proxy.admin.as_ref().unwrap().address();

        let first_response = owned_http_request(&agent_socket, "/first", b"first-result").await;
        assert!(first_response.starts_with(b"HTTP/1.1 200"));
        assert!(first_response.ends_with(b"first-result"));
        let (status, _, body) = operator_http(
            admin_address,
            token,
            Method::GET,
            "/admin/traffic/flows",
            b"",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let first_flows: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(first_flows["flows"].as_array().unwrap().len(), 1);
        let first_id = first_flows["flows"][0]["id"].as_str().unwrap().to_owned();
        assert!(
            first_flows["flows"][0]["url"]
                .as_str()
                .unwrap()
                .ends_with("/first")
        );

        let second_response = owned_http_request(&agent_socket, "/second", b"second-result").await;
        assert!(second_response.starts_with(b"HTTP/1.1 200"));
        assert!(second_response.ends_with(b"second-result"));
        let (status, _, body) = operator_http(
            admin_address,
            token,
            Method::GET,
            "/admin/traffic/flows",
            b"",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let second_flows: Value = serde_json::from_slice(&body).unwrap();
        let rows = second_flows["flows"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        let second_id = rows[0]["id"].as_str().unwrap();
        assert_ne!(second_id, first_id);
        assert!(rows[0]["url"].as_str().unwrap().ends_with("/second"));

        let (status, _, _) = operator_http(
            admin_address,
            token,
            Method::GET,
            &format!("/admin/traffic/flows/{first_id}"),
            b"",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, body) = operator_http(
            admin_address,
            token,
            Method::GET,
            &format!("/admin/traffic/flows/{second_id}/body?side=response"),
            b"",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let response_body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(response_body["available"], true);

        proxy.shutdown().await;
        assert!(!agent_socket.exists());
        assert!(!config.readiness_file.exists());
    })
    .await
    .expect("live configured retention inspector workflow must finish");
}

async fn read_http_head(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> Vec<u8> {
    use tokio::io::AsyncReadExt;

    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await.unwrap());
    }
    head
}

fn masked_client_frame(opcode: OpCode, payload: &[u8]) -> Vec<u8> {
    let key = [13, 17, 23, 31];
    let header = FrameHeader {
        opcode,
        is_final: true,
        mask: Some(key),
        ..FrameHeader::default()
    };
    let mut bytes = Vec::new();
    header.format(payload.len() as u64, &mut bytes).unwrap();
    bytes.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ key[index % key.len()]),
    );
    bytes
}

#[tokio::test]
async fn live_operator_inspector_browses_scopes_and_exports_native_http() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tokio::time::timeout(Duration::from_secs(10), async {
        let directory = tempfile::tempdir().unwrap();
        let mut config = config(directory.path());
        let policy = config.policy_file.as_ref().unwrap();
        std::fs::write(
            policy,
            r#"{"permissions":[{"action":"network:request","resource":"*","effect":"allow"}]}"#,
        )
        .unwrap();
        config.network_guard_enabled = false;
        let agent_socket = directory.path().join("alice.sock");
        config.listeners.push(AgentListener {
            agent_id: "alice".into(),
            socket_path: agent_socket.clone(),
            source_id: None,
        });
        let token = "live-inspector-token";
        let token_path = directory.path().join("operator-token");
        std::fs::write(&token_path, token).unwrap();
        config.admin_port = Some(0);
        config.admin_api_token_file = Some(token_path);

        let origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin_address = origin.local_addr().unwrap();
        let (request_ready, request_seen) = tokio::sync::oneshot::channel();
        let (release_response, response_ready) = tokio::sync::oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let mut received = Vec::new();
            loop {
                let mut block = [0; 1024];
                let size = stream.read(&mut block).await.unwrap();
                assert!(size > 0);
                received.extend_from_slice(&block[..size]);
                if let Some(end) = received.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                    && received.len() >= end + 4 + 11
                {
                    assert_eq!(&received[end + 4..end + 4 + 11], b"native-body");
                    break;
                }
            }
            request_ready.send(()).unwrap();
            response_ready.await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nnative-result",
                )
                .await
                .unwrap();
        });

        let proxy = Proxy::start(config.clone()).await.unwrap();
        let admin_address = proxy.admin.as_ref().unwrap().address();
        let mut client = tokio::net::UnixStream::connect(&agent_socket).await.unwrap();
        let request = format!(
            "POST http://{origin_address}/native?dup=1&dup=2 HTTP/1.1\r\nHost: {origin_address}\r\nContent-Type: text/plain\r\nContent-Length: 11\r\nConnection: close\r\n\r\nnative-body"
        );
        client.write_all(request.as_bytes()).await.unwrap();
        request_seen.await.unwrap();

        let (status, _, body) =
            operator_http(admin_address, token, Method::GET, "/admin/traffic/flows", b"")
                .await;
        assert_eq!(status, StatusCode::OK);
        let pending: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(pending["flows"].as_array().unwrap().len(), 1);
        let row = &pending["flows"][0];
        assert_eq!(row["agent"], "alice");
        assert_eq!(row["method"], "POST");
        assert_eq!(row["state"], "pending");
        let id = row["id"].as_str().unwrap().to_owned();

        let (status, _, _) = operator_http(
            admin_address,
            token,
            Method::PUT,
            "/admin/traffic/scope",
            br#"{"agent":"bob"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (_, _, body) =
            operator_http(admin_address, token, Method::GET, "/admin/traffic/flows", b"").await;
        let hidden: Value = serde_json::from_slice(&body).unwrap();
        assert!(hidden["flows"].as_array().unwrap().is_empty());

        let (status, _, _) = operator_http(
            admin_address,
            token,
            Method::PUT,
            "/admin/traffic/scope",
            br#"{"agent":"alice"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = operator_http(
            admin_address,
            token,
            Method::PUT,
            "/admin/traffic/filter",
            br#"{"user_filter":"~m POST"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (_, _, body) =
            operator_http(admin_address, token, Method::GET, "/admin/traffic/flows", b"").await;
        let filtered: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(filtered["flows"][0]["id"], id);

        let (_, _, body) = operator_http(
            admin_address,
            token,
            Method::GET,
            &format!("/admin/traffic/flows/{id}"),
            b"",
        )
        .await;
        let detail: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(detail["state"], "pending");
        assert_eq!(detail["url"], format!("http://{origin_address}/native?dup=1&dup=2"));
        let (_, _, body) = operator_http(
            admin_address,
            token,
            Method::GET,
            &format!("/admin/traffic/flows/{id}/body?side=request"),
            b"",
        )
        .await;
        let request_body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(request_body["available"], true);
        assert_eq!(request_body["data_base64"], STANDARD.encode(b"native-body"));
        let (_, _, body) = operator_http(
            admin_address,
            token,
            Method::GET,
            &format!("/admin/traffic/flows/{id}/body?side=response"),
            b"",
        )
        .await;
        let response_body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(response_body["available"], false);
        assert_eq!(response_body["reason"], "pending");

        release_response.send(()).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        assert!(response.ends_with(b"native-result"));
        origin_task.await.unwrap();

        let (_, _, body) = operator_http(
            admin_address,
            token,
            Method::GET,
            &format!("/admin/traffic/flows/{id}"),
            b"",
        )
        .await;
        let detail: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(detail["state"], "complete");
        assert_eq!(detail["status"], 200);
        let (_, _, body) = operator_http(
            admin_address,
            token,
            Method::GET,
            &format!("/admin/traffic/flows/{id}/body?side=response"),
            b"",
        )
        .await;
        let response_body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(response_body["available"], true);
        assert_eq!(response_body["data_base64"], STANDARD.encode(b"native-result"));

        for format in [
            "raw",
            "raw_request",
            "raw_response",
            "curl",
            "httpie",
            "har",
            "zhar",
        ] {
            let (status, headers, body) = operator_http(
                admin_address,
                token,
                Method::GET,
                &format!("/admin/traffic/flows/{id}/export?format={format}"),
                b"",
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{format}");
            assert!(
                headers
                    .get("content-disposition")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .contains(&format!("traffic.{format}")),
                "{format}"
            );
            match format {
                "raw" => {
                    assert!(body.windows(b"native-body".len()).any(|part| part == b"native-body"));
                    assert!(body.windows(b"native-result".len()).any(|part| part == b"native-result"));
                }
                "raw_request" | "curl" | "httpie" => {
                    assert!(body.windows(b"native-body".len()).any(|part| part == b"native-body"));
                }
                "raw_response" => {
                    assert!(body.windows(b"native-result".len()).any(|part| part == b"native-result"));
                }
                "har" => {
                    let har: Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(har["log"]["entries"].as_array().unwrap().len(), 1);
                }
                "zhar" => {
                    let mut decoder = ZlibDecoder::new(body.as_ref());
                    let mut decompressed = Vec::new();
                    decoder.read_to_end(&mut decompressed).unwrap();
                    let har: Value = serde_json::from_slice(&decompressed).unwrap();
                    assert_eq!(har["log"]["entries"].as_array().unwrap().len(), 1);
                }
                _ => unreachable!(),
            }
        }

        let (status, _, _) = operator_http(
            admin_address,
            token,
            Method::PUT,
            "/admin/traffic/scope",
            br#"{}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = operator_http(
            admin_address,
            token,
            Method::PUT,
            "/admin/traffic/filter",
            br#"{"user_filter":""}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        proxy.shutdown().await;
        assert!(!agent_socket.exists());
        assert!(!config.readiness_file.exists());
    })
    .await
    .expect("live native inspector workflow must finish");
}

#[tokio::test]
async fn live_operator_inspector_browses_native_websocket_transcript() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use tokio::io::AsyncWriteExt;

    tokio::time::timeout(Duration::from_secs(10), async {
        let directory = tempfile::tempdir().unwrap();
        let mut config = config(directory.path());
        let policy = config.policy_file.as_ref().unwrap();
        std::fs::write(
            policy,
            r#"{"permissions":[{"action":"network:request","resource":"*","effect":"allow"}]}"#,
        )
        .unwrap();
        config.network_guard_enabled = false;
        let agent_socket = directory.path().join("alice.sock");
        config.listeners.push(AgentListener {
            agent_id: "alice".into(),
            socket_path: agent_socket.clone(),
            source_id: None,
        });
        let token = "live-websocket-inspector-token";
        let token_path = directory.path().join("operator-token");
        std::fs::write(&token_path, token).unwrap();
        config.admin_port = Some(0);
        config.admin_api_token_file = Some(token_path);

        let origin = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let head = read_http_head(&mut stream).await;
            assert!(head.starts_with(b"GET /socket?inspector=ws HTTP/1.1\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                )
                .await
                .unwrap();
            let (read, write) = tokio::io::split(stream);
            let mut reader = Reader::new(read, true, None);
            let mut writer = Writer::new(write, false, None);
            let Event::Message(message) = reader.read().await.unwrap() else {
                panic!("client WebSocket message expected");
            };
            message
                .with_text(|text| assert_eq!(text, "client transcript"))
                .unwrap();
            writer
                .message(Message::text_for_send("server transcript"))
                .await
                .unwrap();
            let Event::Close(payload) = reader.read().await.unwrap() else {
                panic!("client WebSocket close expected");
            };
            assert_eq!(payload, 1000_u16.to_be_bytes());
        });

        let proxy = Proxy::start(config.clone()).await.unwrap();
        let admin_address = proxy.admin.as_ref().unwrap().address();
        let mut client = tokio::net::UnixStream::connect(&agent_socket).await.unwrap();
        let request = format!(
            "GET http://{origin_address}/socket?inspector=ws HTTP/1.1\r\nHost: {origin_address}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        );
        client.write_all(request.as_bytes()).await.unwrap();
        let head = read_http_head(&mut client).await;
        assert!(head.starts_with(b"HTTP/1.1 101"));
        let (read, mut write) = tokio::io::split(client);
        let mut reader = Reader::new(read, false, None);
        write
            .write_all(&masked_client_frame(
                OpCode::Data(Data::Text),
                b"client transcript",
            ))
            .await
            .unwrap();
        let Event::Message(message) = reader.read().await.unwrap() else {
            panic!("server WebSocket message expected");
        };
        message
            .with_text(|text| assert_eq!(text, "server transcript"))
            .unwrap();

        let (status, _, body) =
            operator_http(admin_address, token, Method::GET, "/admin/traffic/flows", b"")
                .await;
        assert_eq!(status, StatusCode::OK);
        let flows: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(flows["flows"].as_array().unwrap().len(), 1);
        let id = flows["flows"][0]["id"].as_str().unwrap().to_owned();
        assert_eq!(flows["flows"][0]["agent"], "alice");
        assert_eq!(flows["flows"][0]["state"], "websocket_open");

        let (status, _, body) = operator_http(
            admin_address,
            token,
            Method::GET,
            &format!("/admin/traffic/flows/{id}"),
            b"",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let detail: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(detail["state"], "websocket_open");
        assert_eq!(detail["websocket"]["state"], "open");

        let (status, _, body) = operator_http(
            admin_address,
            token,
            Method::GET,
            &format!("/admin/traffic/flows/{id}/websocket/messages"),
            b"",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let transcript: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(transcript["websocket"]["state"], "open");
        assert_eq!(transcript["messages"].as_array().unwrap().len(), 2);
        assert_eq!(transcript["messages"][0]["from_client"], true);
        assert_eq!(transcript["messages"][0]["type"], "text");
        assert_eq!(transcript["messages"][0]["body"]["size"], 17);
        assert_eq!(transcript["messages"][1]["from_client"], false);
        assert_eq!(transcript["messages"][1]["body"]["size"], 17);

        for (message_id, expected) in [(0, b"client transcript"), (1, b"server transcript")] {
            let (status, _, body) = operator_http(
                admin_address,
                token,
                Method::GET,
                &format!(
                    "/admin/traffic/flows/{id}/websocket/messages/{message_id}/body?offset=0"
                ),
                b"",
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let page: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(page["available"], true);
            assert_eq!(
                page["data_base64"],
                STANDARD.encode(expected),
                "message {message_id}"
            );
            assert_eq!(page["offset"], 0);
            assert_eq!(page["end"], true);
        }

        // Exercise every selected-flow format against this live WebSocket
        // row, including the retained transcript bytes. The component tests
        // already cover synthetic rows; this keeps the real upgrade path in
        // the acceptance evidence.
        for format in [
            "raw",
            "raw_request",
            "raw_response",
            "curl",
            "httpie",
            "har",
            "zhar",
        ] {
            let (status, headers, body) = operator_http(
                admin_address,
                token,
                Method::GET,
                &format!("/admin/traffic/flows/{id}/export?format={format}"),
                b"",
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{format}");
            assert!(
                headers
                    .get("content-disposition")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .contains(&format!("traffic.{format}")),
                "{format}"
            );
            match format {
                "raw" => {
                    assert!(body.windows(b"client transcript".len()).any(|part| {
                        part == b"client transcript"
                    }));
                    assert!(body.windows(b"server transcript".len()).any(|part| {
                        part == b"server transcript"
                    }));
                }
                "raw_request" | "curl" | "httpie" => {
                    assert!(body.windows(b"/socket?inspector=ws".len()).any(|part| {
                        part == b"/socket?inspector=ws"
                    }));
                }
                "raw_response" => {
                    assert!(body.windows(b"101 Switching Protocols".len()).any(|part| {
                        part == b"101 Switching Protocols"
                    }));
                }
                "har" => {
                    let har: Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(har["log"]["entries"].as_array().unwrap().len(), 1);
                    let messages = har["log"]["entries"][0]["_webSocketMessages"]
                        .as_array()
                        .unwrap();
                    assert_eq!(messages.len(), 2);
                    assert_eq!(messages[0]["data"], "client transcript");
                    assert_eq!(messages[1]["data"], "server transcript");
                }
                "zhar" => {
                    let mut decoder = ZlibDecoder::new(body.as_ref());
                    let mut decompressed = Vec::new();
                    decoder.read_to_end(&mut decompressed).unwrap();
                    let har: Value = serde_json::from_slice(&decompressed).unwrap();
                    assert_eq!(har["log"]["entries"].as_array().unwrap().len(), 1);
                    let messages = har["log"]["entries"][0]["_webSocketMessages"]
                        .as_array()
                        .unwrap();
                    assert_eq!(messages.len(), 2);
                    assert_eq!(messages[0]["data"], "client transcript");
                    assert_eq!(messages[1]["data"], "server transcript");
                }
                _ => unreachable!(),
            }
        }

        write
            .write_all(&masked_client_frame(
                OpCode::Control(tungstenite::protocol::frame::coding::Control::Close),
                &1000_u16.to_be_bytes(),
            ))
            .await
            .unwrap();
        let Event::Close(payload) = reader.read().await.unwrap() else {
            panic!("server WebSocket close expected");
        };
        assert_eq!(payload, 1000_u16.to_be_bytes());
        drop(reader);
        drop(write);
        origin_task.await.unwrap();

        let (status, _, body) = operator_http(
            admin_address,
            token,
            Method::GET,
            &format!("/admin/traffic/flows/{id}"),
            b"",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let closed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(closed["state"], "complete");
        assert_eq!(closed["websocket"]["state"], "closed");
        assert_eq!(closed["websocket"]["closed_by_client"], true);
        assert_eq!(closed["websocket"]["close_code"], 1000);
        assert_eq!(closed["websocket"]["messages_meta"]["count"], 2);

        proxy.shutdown().await;
        assert!(!agent_socket.exists());
        assert!(!config.readiness_file.exists());
    })
    .await
    .expect("live native WebSocket inspector workflow must finish");
}
