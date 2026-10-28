use super::*;
use crate::{Config, Proxy};
use std::{collections::HashSet, path::Path, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

const LIMIT: Duration = Duration::from_secs(5);

pub(crate) fn config(directory: &Path) -> Config {
    let policy = directory.join("policy.json");
    std::fs::write(
        &policy,
        json!({
            "permissions":[{"action":"network:request","resource":"*","effect":"allow"}],
        "addons":{"request_logger":{"quiet_hosts":{"hosts":["forged.invalid"]}}}
        })
        .to_string(),
    )
    .unwrap();
    serde_json::from_value(json!({
        "listeners":[{"agent_id":"alice","source_id":"192.0.2.20","socket_path":directory.join("alice.sock")}],
        "policy_file":policy,"data_dir":directory.join("data"),"readiness_file":directory.join("ready"),
        "audit_log_path":directory.join("audit.jsonl"),"flow_store_enabled":false,
        "flow_store_db_path":directory.join("unused.sqlite3"),
        "circuit_breaker_enabled":false,"circuit_state_file":""
    })).unwrap()
}

pub(crate) fn records(runtime: &Runtime, directory: &Path) -> Vec<Value> {
    assert!(runtime.audit.wait_for_drain(LIMIT).unwrap());
    std::fs::read_to_string(directory.join("audit.jsonl"))
        .unwrap()
        .lines()
        .map(|line| crate::audit::parse_record(line).unwrap())
        .collect()
}

pub(crate) async fn head(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    timeout(LIMIT, async {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(stream.read_u8().await.unwrap());
        }
        bytes
    })
    .await
    .unwrap()
}

pub(crate) fn connections(rows: &[Value], leg: &str, state: &str) -> Vec<Value> {
    rows.iter()
        .filter(|row| {
            row["event"] == "network.connection"
                && row["details"]["leg"] == leg
                && (row["details"]["state"] == state
                    || (state == "terminal"
                        && matches!(row["details"]["state"].as_str(), Some("closed" | "failed"))))
        })
        .map(|row| row["details"].clone())
        .collect()
}

pub(crate) fn assert_pairs(rows: &[Value]) {
    let opened: Vec<_> = rows
        .iter()
        .filter(|row| row["event"] == "network.connection" && row["details"]["state"] == "open")
        .collect();
    let ids: HashSet<_> = opened
        .iter()
        .map(|row| row["details"]["connection_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), opened.len(), "duplicate open records");
    for open in opened {
        let details = &open["details"];
        let ended: Vec<_> = rows
            .iter()
            .filter(|row| {
                row["event"] == "network.connection"
                    && row["details"]["connection_id"] == details["connection_id"]
                    && matches!(row["details"]["state"].as_str(), Some("closed" | "failed"))
            })
            .collect();
        assert_eq!(ended.len(), 1, "one terminal record per real connection");
        let end = &ended[0]["details"];
        for field in [
            "instance_id",
            "runtime_id",
            "started_at",
            "leg",
            "transport",
            "client_connection_id",
        ] {
            assert_eq!(details[field], end[field], "{field}");
        }
        assert!(!details["started_at"].as_str().unwrap().is_empty());
        assert!(details["ended_at"].is_null());
        assert!(end["ended_at"].is_string());
        assert_eq!(open["schema_version"], 2);
        assert_eq!(open["agent"], "alice");
        assert_eq!(
            details["attribution"]["trusted_transport_identity"],
            "alice"
        );
        assert_eq!(details["attribution"]["initiator"], "unknown");
        assert_eq!(details["ingress"], "agent-uds");
    }
}

#[tokio::test]
async fn reused_http1_ingress_quieting_real_peers_and_flow_links() {
    let directory = tempfile::tempdir().unwrap();
    let (origin, address) = crate::test_owned_endpoint::bind().await;
    // localhost resolves to the owned ::1 listener in gVisor. Otherwise retain
    // the physical test address without requiring a DNS fixture.
    let authority = if address.is_ipv6() {
        format!("localhost:{}", address.port())
    } else {
        address.to_string()
    };
    let peer = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut socket, _) = origin.accept().await.unwrap();
            assert!(head(&mut socket).await.starts_with(b"GET /"));
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            assert_eq!(
                socket.read_u8().await.unwrap_err().kind(),
                std::io::ErrorKind::UnexpectedEof
            );
        }
    });
    let proxy = Proxy::start(config(directory.path())).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let mut client = UnixStream::connect(directory.path().join("alice.sock"))
        .await
        .unwrap();
    for path in ["/one", "/two"] {
        client.write_all(format!("GET http://{authority}{path} HTTP/1.1\r\nHost: forged.invalid\r\nX-SafeYolo-Agent: bob\r\n\r\n").as_bytes()).await.unwrap();
        assert!(head(&mut client).await.starts_with(b"HTTP/1.1 200"));
    }
    let open_rows = records(&runtime, directory.path());
    assert_eq!(connections(&open_rows, "client_to_proxy", "open").len(), 1);
    assert!(connections(&open_rows, "client_to_proxy", "closed").is_empty());
    drop(client);
    timeout(LIMIT, peer).await.unwrap().unwrap();
    proxy.shutdown().await;
    let rows = records(&runtime, directory.path());
    assert_pairs(&rows);
    let clients = connections(&rows, "client_to_proxy", "open");
    let servers = connections(&rows, "proxy_to_upstream", "open");
    assert_eq!(clients.len(), 1);
    // The current H1 implementation opens two actual upstream sockets. Only
    // the ingress is reused; telemetry must describe that existing behavior.
    assert_eq!(servers.len(), 2);
    assert_eq!(clients[0]["transport"], "unix");
    assert!(clients[0]["resolved_peer"].is_null());
    assert_eq!(clients[0]["local_endpoint"]["type"], "unix");
    let flows: Vec<_> = rows
        .iter()
        .filter(|row| row["event"] == "traffic.flow")
        .collect();
    assert_eq!(flows.len(), 2);
    for server in &servers {
        assert_eq!(server["requested_target"], authority);
        assert_eq!(server["resolved_origin_peer"], address.to_string());
        assert_eq!(
            server["resolved_peer"],
            server["remote_endpoint"]["address"]
        );
        assert_eq!(server["client_connection_id"], clients[0]["connection_id"]);
        assert!(server["local_endpoint"]["address"].is_string());
        assert!(
            flows
                .iter()
                .any(|flow| flow["details"]["server_connection_id"] == server["connection_id"])
        );
    }
    for flow in flows {
        assert_eq!(
            flow["details"]["client_connection_id"],
            clients[0]["connection_id"]
        );
        assert_eq!(flow["details"]["runtime_id"], runtime.instance_id);
    }
    assert!(!rows.iter().any(|row| matches!(
        row["event"].as_str(),
        Some("traffic.request" | "traffic.response")
    )));
    assert!(!directory.path().join("unused.sqlite3").exists());
}

#[tokio::test]
async fn failed_dial_keeps_attempt_id_and_flow_without_response() {
    let directory = tempfile::tempdir().unwrap();
    let (listener, address) = crate::test_owned_endpoint::bind().await;
    drop(listener);
    let proxy = Proxy::start(config(directory.path())).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let mut client = UnixStream::connect(directory.path().join("alice.sock"))
        .await
        .unwrap();
    client
        .write_all(
            format!(
                "GET http://{address}/ HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut reply = Vec::new();
    timeout(LIMIT, client.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert!(reply.starts_with(b"HTTP/1.1 502"));
    drop(client);
    proxy.shutdown().await;
    let rows = records(&runtime, directory.path());
    let failed = connections(&rows, "proxy_to_upstream", "failed");
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0]["error"], "connect_failed");
    assert!(failed[0]["remote_endpoint"].is_null());
    assert!(failed[0]["resolved_origin_peer"].is_null());
    assert!(connections(&rows, "proxy_to_upstream", "open").is_empty());
    let flows: Vec<_> = rows
        .iter()
        .filter(|row| row["event"] == "traffic.flow")
        .collect();
    assert_eq!(flows.len(), 1);
    assert_eq!(
        flows[0]["details"]["server_connection_id"],
        failed[0]["connection_id"]
    );
    assert!(!rows.iter().any(|row| row["event"] == "traffic.response"));
}

#[tokio::test]
async fn parent_connect_reports_physical_parent_and_real_tunnel_lifetime() {
    for refused in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let (parent, address) = crate::test_owned_endpoint::bind().await;
        let mut configuration = config(directory.path());
        configuration.parent_proxy = Some(format!("http://{address}"));
        configuration.ignore_hosts = vec!["origin.invalid:443".into()];
        let (release, hold) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let (mut socket, _) = parent.accept().await.unwrap();
            assert!(
                head(&mut socket)
                    .await
                    .starts_with(b"CONNECT origin.invalid:443 HTTP/1.1")
            );
            socket
                .write_all(if refused {
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
                } else {
                    b"HTTP/1.1 200 OK\r\n\r\n"
                })
                .await
                .unwrap();
            if !refused {
                assert_eq!(socket.read_u8().await.unwrap(), 42);
                socket.write_u8(43).await.unwrap();
                let _ = hold.await;
            }
        });
        let proxy = Proxy::start(configuration).await.unwrap();
        let runtime = proxy.runtime.read().unwrap().clone();
        let mut client = UnixStream::connect(directory.path().join("alice.sock"))
            .await
            .unwrap();
        client
            .write_all(b"CONNECT origin.invalid:443 HTTP/1.1\r\nHost: origin.invalid:443\r\n\r\n")
            .await
            .unwrap();
        assert!(head(&mut client).await.starts_with(if refused {
            b"HTTP/1.1 502"
        } else {
            b"HTTP/1.1 200"
        }));
        if !refused {
            client.write_u8(42).await.unwrap();
            assert_eq!(timeout(LIMIT, client.read_u8()).await.unwrap().unwrap(), 43);
            let rows = records(&runtime, directory.path());
            assert_eq!(connections(&rows, "proxy_to_upstream", "open").len(), 1);
            assert!(connections(&rows, "proxy_to_upstream", "closed").is_empty());
            assert!(connections(&rows, "client_to_proxy", "closed").is_empty());
        }
        drop(client);
        let _ = release.send(());
        timeout(LIMIT, peer).await.unwrap().unwrap();
        proxy.shutdown().await;
        let rows = records(&runtime, directory.path());
        assert_pairs(&rows);
        let servers = connections(
            &rows,
            "proxy_to_upstream",
            if refused { "failed" } else { "closed" },
        );
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0]["route"], "parent");
        assert_eq!(servers[0]["requested_target"], "origin.invalid:443");
        assert_eq!(servers[0]["resolved_peer"], address.to_string());
        assert_eq!(
            servers[0]["remote_endpoint"]["address"],
            address.to_string()
        );
        assert!(servers[0]["resolved_origin_peer"].is_null());
        if refused {
            assert_eq!(servers[0]["error"], "parent_connection_failed");
        }
        let flows: Vec<_> = rows
            .iter()
            .filter(|row| row["event"] == "traffic.flow")
            .collect();
        assert_eq!(flows.len(), 1);
        assert_eq!(
            flows[0]["details"]["server_connection_id"],
            servers[0]["connection_id"]
        );
    }
}

#[tokio::test]
async fn installed_namespace_survives_reload_and_changes_runtime_on_restart() {
    let directory = tempfile::tempdir().unwrap();
    let mut configuration = config(directory.path());
    std::fs::write(
        configuration.policy_file.as_ref().unwrap(),
        json!({
            "permissions":[{"action":"network:request","resource":"*","effect":"deny"}]
        })
        .to_string(),
    )
    .unwrap();
    configuration.native_settings = Some(crate::native_config::Settings::default());
    configuration.native_config_dir = Some(directory.path().to_owned());
    let data = configuration.data_dir();
    std::fs::create_dir_all(&data).unwrap();
    let instance_id = "sy-0123456789abcdef0123456789abcdef";
    std::fs::write(data.join("instance_id"), instance_id).unwrap();
    let mut runtimes = HashSet::new();
    for _ in 0..2 {
        let mut proxy = Proxy::start(configuration.clone()).await.unwrap();
        let runtime = proxy.runtime.read().unwrap().clone();
        assert!(runtimes.insert(runtime.instance_id.clone()));
        for _ in 0..2 {
            let mut client = UnixStream::connect(directory.path().join("alice.sock"))
                .await
                .unwrap();
            client.write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n").await.unwrap();
            let mut reply = Vec::new();
            timeout(LIMIT, client.read_to_end(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert!(reply.starts_with(b"HTTP/1.1 403"));
            drop(client);
            proxy.reload(configuration.clone()).await.unwrap();
            let current = proxy.runtime.read().unwrap().clone();
            assert!(Arc::ptr_eq(
                current.connection_events.as_ref().unwrap(),
                runtime.connection_events.as_ref().unwrap()
            ));
        }
        proxy.shutdown().await;
        let rows = records(&runtime, directory.path());
        let current: Vec<_> = rows
            .into_iter()
            .filter(|row| row["details"]["runtime_id"] == runtime.instance_id)
            .collect();
        assert_pairs(&current);
        assert_eq!(connections(&current, "client_to_proxy", "open").len(), 2);
        assert!(
            !current
                .iter()
                .any(|row| row["details"]["leg"] == "proxy_to_upstream")
        );
        let flows: Vec<_> = current
            .iter()
            .filter(|row| row["event"] == "traffic.flow")
            .collect();
        assert_eq!(flows.len(), 2);
        assert!(
            flows
                .iter()
                .all(|flow| flow["details"]["server_connection_id"].is_null())
        );
        assert!(
            current
                .iter()
                .all(|row| row["details"]["instance_id"] == instance_id)
        );
    }
}

#[tokio::test]
async fn idle_ingress_has_lifecycle_without_a_request_or_synthetic_peer() {
    let directory = tempfile::tempdir().unwrap();
    let proxy = Proxy::start(config(directory.path())).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let client = UnixStream::connect(directory.path().join("alice.sock"))
        .await
        .unwrap();
    timeout(LIMIT, async {
        loop {
            let rows = records(&runtime, directory.path());
            if !connections(&rows, "client_to_proxy", "open").is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(client);
    proxy.shutdown().await;
    let rows = records(&runtime, directory.path());
    assert_pairs(&rows);
    let clients = connections(&rows, "client_to_proxy", "closed");
    assert_eq!(clients.len(), 1);
    assert_eq!(
        clients[0]["remote_endpoint"],
        json!({"type":"unix","path":null})
    );
    assert!(!rows.iter().any(|row| row["event"] == "traffic.flow"));
}

#[tokio::test]
async fn failed_protocol_keeps_the_established_tcp_connection_and_flow_id() {
    for tls in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let (origin, address) = crate::test_owned_endpoint::bind().await;
        let peer = tokio::spawn(async move {
            let (mut socket, _) = origin.accept().await.unwrap();
            if tls {
                let mut header = [0; 5];
                socket.read_exact(&mut header).await.unwrap();
                let mut hello = vec![0; u16::from_be_bytes([header[3], header[4]]) as usize];
                socket.read_exact(&mut hello).await.unwrap();
            } else {
                head(&mut socket).await;
            }
            // Reject the protocol after receiving its first message, keeping the
            // socket open until the proxy closes it after its parser error.
            socket
                .write_all(b"invalid wire response\r\n\r\n")
                .await
                .unwrap();
            let mut remaining = Vec::new();
            let _ = socket.read_to_end(&mut remaining).await;
        });
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let certificate = params.self_signed(&key).unwrap();
        let trust = directory.path().join("trust.pem");
        std::fs::write(&trust, certificate.pem()).unwrap();
        let interception = directory.path().join("interception.pem");
        std::fs::write(
            &interception,
            format!("{}{}", key.serialize_pem(), certificate.pem()),
        )
        .unwrap();
        let mut configuration = config(directory.path());
        configuration.upstream_ca_file = tls.then_some(trust);
        configuration.tls_ca_file = tls.then_some(interception);
        let proxy = Proxy::start(configuration).await.unwrap();
        let runtime = proxy.runtime.read().unwrap().clone();
        let mut client = UnixStream::connect(directory.path().join("alice.sock"))
            .await
            .unwrap();
        client
            .write_all(
                format!(
                    "GET {}://{address}/ HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n",
                    if tls { "https" } else { "http" }
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut reply = Vec::new();
        timeout(LIMIT, client.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert!(
            reply.starts_with(b"HTTP/1.1 502"),
            "{}",
            String::from_utf8_lossy(&reply)
        );
        drop(client);
        timeout(LIMIT, peer).await.unwrap().unwrap();
        proxy.shutdown().await;
        let rows = records(&runtime, directory.path());
        assert_pairs(&rows);
        let servers = connections(&rows, "proxy_to_upstream", "failed");
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0]["resolved_origin_peer"], address.to_string());
        assert_eq!(
            servers[0]["error"],
            if tls {
                "origin_tls_failed"
            } else {
                "http_error"
            }
        );
        assert!(servers[0]["tls_server_name"].is_null());
        assert!(servers[0]["tls_sessions"].is_null());
        let flows: Vec<_> = rows
            .iter()
            .filter(|row| row["event"] == "traffic.flow")
            .collect();
        assert_eq!(flows.len(), 1);
        assert_eq!(
            flows[0]["details"]["server_connection_id"],
            servers[0]["connection_id"]
        );
    }
}
