use super::*;
use crate::jobs::{network, tests::spec};
use std::{path::Path, time::Duration};
use tokio::net::TcpListener;

fn limits() -> ServiceLimits {
    ServiceLimits {
        services: vec!["simple".into()],
        max_calls: 5,
        max_request_bytes: MESSAGE_BYTES,
        max_response_bytes: 100_000,
    }
}

async fn rpc(path: &Path, value: Value) -> Value {
    let mut stream = UnixStream::connect(path).await.unwrap();
    let bytes = serde_json::to_vec(&value).unwrap();
    stream.write_u32(bytes.len() as u32).await.unwrap();
    stream.write_all(&bytes).await.unwrap();
    let length = stream.read_u32().await.unwrap();
    assert!(length as usize <= MESSAGE_BYTES);
    let mut bytes = vec![0; length as usize];
    stream.read_exact(&mut bytes).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn selected_spec() -> crate::jobs::JobSpec {
    let mut job = spec();
    job.gate_id = "proof".into();
    job
}

#[tokio::test]
async fn complete_large_evidence_is_chunked_and_off_scope_calls_are_denied() {
    let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let origin = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = origin.local_addr().unwrap().port();
    let config = network::tests::config(root.path(), port);
    let proxy = crate::Proxy::start(crate::native_config::read(&config).unwrap())
        .await
        .unwrap();
    let bytes = serde_json::to_vec(&json!({"body":"a".repeat(80_000)})).unwrap();
    let expected = bytes.clone();
    let provider = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(stream.read_u8().await.unwrap());
        }
        let header = String::from_utf8(header).unwrap().to_ascii_lowercase();
        assert!(header.contains("authorization: bearer synthetic-job-provider-secret"));
        assert!(!header.contains("sgw_"));
        stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"capture-1\"\r\nConnection: close\r\n\r\n", bytes.len()).as_bytes()).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), origin.accept())
                .await
                .is_err()
        );
    });
    let mut client = network::Client::connect_mediated(
        &config,
        root.path(),
        &selected_spec(),
        &"1".repeat(32),
        &["parent-check".into()],
    )
    .await
    .unwrap();
    let captures = Captures::default();
    let socket = root.path().join("bridge.sock");
    let bridge = Bridge::new(
        UnixListener::bind(&socket).unwrap(),
        &client,
        limits(),
        captures.clone(),
    )
    .unwrap();
    let serving = tokio::spawn(bridge.serve());
    let call = |path: &str| json!({"kind":"service","service":"simple","method":"GET","url":format!("http://127.0.0.1:{port}{path}")});
    let reply = rpc(&socket, call("/value")).await;
    assert_eq!(reply["ok"], true, "{reply}");
    let handle = reply["value"]["id"].as_str().unwrap();
    let mut captured = Vec::new();
    while captured.len() < expected.len() {
        let chunk = rpc(
            &socket,
            json!({"kind":"read","id":handle,"offset":captured.len(),"length":CHUNK_BYTES}),
        )
        .await;
        assert_eq!(chunk["ok"], true, "{chunk}");
        captured.extend(
            STANDARD
                .decode(chunk["value"]["data_base64"].as_str().unwrap())
                .unwrap(),
        );
    }
    assert_eq!(captured, expected);
    assert_eq!(reply["value"]["sha256"], digest(&captured));
    for value in [
        json!({"kind":"read","id":handle,"offset":0,"length":CHUNK_BYTES+1}),
        json!({"kind":"read","id":handle,"offset":expected.len()+1,"length":1}),
        json!({"kind":"service","service":"unselected","method":"GET","url":format!("http://127.0.0.1:{port}/value")}),
        json!({"kind":"service","service":"simple","method":"CONNECT","url":"https://api.github.com"}),
        call("/write"),
        json!({"kind":"service","service":"simple","method":"POST","url":format!("http://127.0.0.1:{port}/value")}),
        json!({"kind":"service","service":"simple","method":"GET","url":"http://denied.example/value"}),
    ] {
        assert_eq!(rpc(&socket, value).await["ok"], false);
    }
    client.confirm_current().await.unwrap();
    serving.abort();
    assert!(serving.await.unwrap_err().is_cancelled());
    client.close().await.unwrap();
    provider.await.unwrap();
    let records = captures.finish().unwrap();
    assert_eq!(records[0].source_revision.as_deref(), Some("\"capture-1\""));
    assert_eq!(
        STANDARD
            .decode(records[0].retained_base64.as_ref().unwrap())
            .unwrap(),
        expected
    );
    assert_eq!(records[0].error, None);
    assert!(records.iter().skip(1).all(|record| record.error.is_some()));
    proxy.shutdown().await;
}

#[tokio::test]
async fn policy_revocation_closes_a_held_response_and_discards_late_evidence() {
    let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let origin = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = origin.local_addr().unwrap().port();
    let config = network::tests::config(root.path(), port);
    let mut proxy = crate::Proxy::start(crate::native_config::read(&config).unwrap())
        .await
        .unwrap();
    let mut client = network::Client::connect_mediated(
        &config,
        root.path(),
        &selected_spec(),
        &"2".repeat(32),
        &[],
    )
    .await
    .unwrap();
    let captures = Captures::default();
    let socket = root.path().join("bridge.sock");
    let bridge = Bridge::new(
        UnixListener::bind(&socket).unwrap(),
        &client,
        limits(),
        captures.clone(),
    )
    .unwrap();
    let serving = tokio::spawn(bridge.serve());
    let pending = tokio::spawn(async move {
        rpc(&socket, json!({"kind":"service","service":"simple","method":"GET","url":format!("http://127.0.0.1:{port}/value")})).await
    });
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), origin.accept())
        .await
        .unwrap()
        .unwrap();
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(stream.read_u8().await.unwrap());
    }
    let policy = root.path().join("policy.toml");
    let source = std::fs::read_to_string(&policy).unwrap();
    std::fs::write(&policy, source.replace("[agents.\"gate:proof\".services.simple]\ncapability = \"reader\"\ntoken = \"job-secret\"", "")).unwrap();
    assert!(proxy.reload_policy_if_changed().await.unwrap());
    // Listener teardown gives accepted transports a ten-second grace before
    // cancelling and joining them. Wait for that existing cleanup contract.
    tokio::time::timeout(Duration::from_secs(12), client.revoked())
        .await
        .unwrap();
    // The provider's delayed successful bytes cannot restore the old listener.
    let _ = stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        .await;
    let reply = tokio::time::timeout(Duration::from_secs(5), pending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply["ok"], false, "{reply}");
    serving.abort();
    assert!(serving.await.unwrap_err().is_cancelled());
    client.close().await.unwrap();
    let records = captures.finish().unwrap();
    assert_eq!(records.len(), 1);
    assert!(records[0].request_started);
    assert!(records[0].error.is_some());
    assert!(records[0].response_sha256.is_none());
    // The unchanged call under a fresh delegation has no saved grant now.
    let next = network::Client::connect_mediated(
        &config,
        root.path(),
        &selected_spec(),
        &"3".repeat(32),
        &[],
    )
    .await
    .unwrap();
    assert!(next.service_access().unwrap().1.is_empty());
    next.close().await.unwrap();
    proxy.shutdown().await;
}

#[test]
fn adopted_limits_are_finite_and_message_sizes_fit_both_abis() {
    let mut value = limits();
    assert!(value.validate().is_ok());
    value.max_request_bytes = MESSAGE_BYTES + 1;
    assert!(value.validate().is_err());
    value.max_request_bytes = MESSAGE_BYTES;
    value.max_calls = usize::MAX;
    assert!(value.validate().is_err());
    assert!(serde_json::to_vec(&json!({"ok":true,"value":{"data_base64":STANDARD.encode(vec![0;CHUNK_BYTES]),"total_bytes":usize::MAX}})).unwrap().len() < MESSAGE_BYTES);
}

#[tokio::test]
async fn oversized_provider_evidence_is_unavailable_and_never_truncated() {
    let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let origin = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = origin.local_addr().unwrap().port();
    let config = network::tests::config(root.path(), port);
    let proxy = crate::Proxy::start(crate::native_config::read(&config).unwrap())
        .await
        .unwrap();
    let provider = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(stream.read_u8().await.unwrap());
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nabcde")
            .await
            .unwrap();
    });
    let client = network::Client::connect_mediated(
        &config,
        root.path(),
        &selected_spec(),
        &"4".repeat(32),
        &[],
    )
    .await
    .unwrap();
    let captures = Captures::default();
    let mut selected = limits();
    selected.max_calls = 1;
    selected.max_response_bytes = 4;
    let bridge = Bridge::new(
        UnixListener::bind(root.path().join("bridge.sock")).unwrap(),
        &client,
        selected,
        captures.clone(),
    )
    .unwrap();
    let url = format!("http://127.0.0.1:{port}/value");
    assert!(
        bridge
            .service("simple".into(), "GET".into(), url.clone(), String::new())
            .await
            .unwrap_err()
            .to_string()
            .contains("response limit")
    );
    assert!(
        bridge
            .service("simple".into(), "GET".into(), url, String::new())
            .await
            .unwrap_err()
            .to_string()
            .contains("call limit")
    );
    let records = captures.finish().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].status, Some(200));
    assert!(records[0].error.is_some());
    assert!(records[0].response_sha256.is_none());
    assert!(records[0].retained_base64.is_none());
    assert!(bridge.read(&records[0].id, 0, 1).is_err());
    client.close().await.unwrap();
    provider.await.unwrap();
    proxy.shutdown().await;
}

#[tokio::test]
async fn interrupted_effect_retains_uncertainty_separately_from_findings() {
    let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let origin = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = origin.local_addr().unwrap().port();
    let config = network::tests::config(root.path(), port);
    let service = root.path().join("services/simple.yaml");
    let definition = std::fs::read_to_string(&service)
        .unwrap()
        .replace("methods: [GET]", "methods: [GET, POST]");
    std::fs::write(service, definition).unwrap();
    let proxy = crate::Proxy::start(crate::native_config::read(&config).unwrap())
        .await
        .unwrap();
    let client = network::Client::connect_mediated(
        &config,
        root.path(),
        &selected_spec(),
        &"5".repeat(32),
        &[],
    )
    .await
    .unwrap();
    let captures = Captures::default();
    let bridge = Bridge::new(
        UnixListener::bind(root.path().join("bridge.sock")).unwrap(),
        &client,
        limits(),
        captures.clone(),
    )
    .unwrap();
    let mut pending = Box::pin(bridge.service(
        "simple".into(),
        "POST".into(),
        format!("http://127.0.0.1:{port}/value"),
        STANDARD.encode(b"{}"),
    ));
    let held = async {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(stream.read_u8().await.unwrap());
        }
        stream
    };
    let mut provider = tokio::select! {
        stream = held => stream,
        result = &mut pending => panic!("effect completed before response: {result:?}"),
        _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("effect did not reach controlled provider"),
    };
    drop(pending);
    client.close().await.unwrap();
    let _ = provider
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        .await;
    let records = captures.finish().unwrap();
    assert_eq!(records[0].effect_outcome, "uncertain");
    assert!(records[0].request_started);
    assert_eq!(records[0].request_sha256, digest(b"{}"));
    assert_eq!(records[0].request_body_base64, STANDARD.encode(b"{}"));
    assert!(records[0].error.is_some());
    assert!(records[0].response_sha256.is_none());
    proxy.shutdown().await;
}
