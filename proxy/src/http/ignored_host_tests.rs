//! Owned H1 direct-CONNECT lifecycle checks. These do not claim parent-route,
//! ordinary HTTP, post-resolution-only matching, or pending-dial cancellation.

use crate::{Config, Proxy, Runtime};
use serde_json::{Value, json};
use std::{
    path::Path,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixStream},
    time::timeout,
};

const LIMIT: Duration = Duration::from_secs(5);
const HOST: &str = "127.0.0.2";
const SOURCE: &str = "192.0.2.10";

fn config(directory: &Path, port: u16, matched: bool, allowed: bool) -> Config {
    std::fs::write(
        directory.join("policy.json"),
        json!({"permissions":[{"action":"network:request","resource":"*",
            "effect":if allowed { "allow" } else { "deny" }}]})
        .to_string(),
    )
    .unwrap();
    serde_json::from_value(json!({
        "listeners":[{"agent_id":"alice","source_id":SOURCE,
            "socket_path":directory.join("alice.sock")}],
        "policy_file":directory.join("policy.json"),
        "readiness_file":directory.join("ready"),
        "audit_log_path":directory.join("audit.jsonl"),
        "event_log":directory.join("events.jsonl"),
        "flow_store_enabled":false,"flow_store_db_path":directory.join("unused.sqlite3"),
        "circuit_breaker_enabled":false,"circuit_state_file":"",
        "ignore_hosts":if matched { vec![format!("{HOST}:{port}")] } else { vec![] }
    }))
    .unwrap()
}

async fn listener() -> TcpListener {
    TcpListener::bind((std::net::Ipv4Addr::new(127, 0, 0, 2), 0))
        .await
        .unwrap()
}

async fn accept(listener: &TcpListener) -> TcpStream {
    timeout(LIMIT, listener.accept()).await.unwrap().unwrap().0
}

async fn request(directory: &Path, port: u16) -> (UnixStream, Vec<u8>) {
    let mut client = UnixStream::connect(directory.join("alice.sock"))
        .await
        .unwrap();
    client
        .write_all(
            format!("CONNECT {HOST}:{port} HTTP/1.1\r\nHost: {HOST}:{port}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let head = timeout(LIMIT, async {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(client.read_u8().await.unwrap());
        }
        head
    })
    .await
    .unwrap();
    (client, head)
}

async fn connect(directory: &Path, port: u16) -> UnixStream {
    let (client, head) = request(directory, port).await;
    assert!(
        head.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&head)
    );
    client
}

async fn remaining(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut bytes = Vec::new();
    timeout(LIMIT, stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    bytes
}

fn records(directory: &Path, name: &str) -> Vec<Value> {
    let contents = match std::fs::read_to_string(directory.join(name)) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => panic!("owned record read failed: {error}"),
    };
    contents
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn lifecycle(runtime: &Runtime, directory: &Path) -> Vec<Value> {
    writer_lifecycle(&runtime.audit, directory)
}

fn writer_lifecycle(writer: &crate::audit::Writer, directory: &Path) -> Vec<Value> {
    assert!(writer.wait_for_drain(LIMIT).unwrap());
    records(directory, "audit.jsonl")
        .into_iter()
        .filter(|row| row["addon"] == "ignored-host-logger")
        .collect()
}

async fn wait_lifecycle(runtime: &Runtime, directory: &Path, count: usize) -> Vec<Value> {
    timeout(LIMIT, async {
        loop {
            let rows = lifecycle(runtime, directory);
            assert!(
                rows.len() <= count,
                "unexpected duplicate lifecycle events: {rows:?}"
            );
            if rows.len() == count {
                return rows;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap()
}

// Compare the complete source envelope and key order. The timestamp must parse;
// duration is the observed nonnegative integer bounded by this owned operation.
// Error wording is checked by the individual control before reuse here.
fn check(row: &Value, phase: &str, port: u16, elapsed: Duration) {
    let timestamp = row["ts"].as_str().unwrap();
    time::OffsetDateTime::parse(timestamp, &time::format_description::well_known::Rfc3339).unwrap();
    let (severity, verb) = match phase {
        "start" => ("medium", "connected to"),
        "error" => ("medium", "failed for"),
        "end" => ("low", "disconnected from"),
        _ => unreachable!(),
    };
    let mut details = json!({"port":port,"transport":"tcp","client":SOURCE});
    if phase == "end" {
        let duration = row["details"]["duration_ms"].as_u64().unwrap();
        assert!(u128::from(duration) <= elapsed.as_millis() + 2);
        details["duration_ms"] = json!(duration);
    } else if phase == "error" {
        let error = row["details"]["error"].as_str().unwrap();
        assert!(!error.is_empty());
        assert_eq!(crate::network_guard::sanitize(error), error);
        details["error"] = json!(error);
    }
    let expected = json!({
        "schema_version":1,"ts":timestamp,"event":format!("traffic.passthrough_{phase}"),
        "kind":"traffic","severity":severity,
        "summary":format!("TLS passthrough {verb} {HOST}:{port}"),
        "agent":"alice","addon":"ignored-host-logger","host":HOST,"details":details
    });
    assert_eq!(row, &expected);
    assert_eq!(
        serde_json::to_string(row).unwrap(),
        serde_json::to_string(&expected).unwrap()
    );
}

fn clean(directory: &Path) {
    assert!(!directory.join("alice.sock").exists());
    assert!(!directory.join("ready").exists());
}

#[tokio::test]
async fn matched_server_first_preserves_both_half_close_orders() {
    for server_half_first in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let origin = listener().await;
        let port = origin.local_addr().unwrap().port();
        let proxy = Proxy::start(config(directory.path(), port, true, true))
            .await
            .unwrap();
        let runtime = proxy.runtime.read().unwrap().clone();
        let started = Instant::now();
        let mut client = connect(directory.path(), port).await;
        let mut peer = accept(&origin).await;
        let start = wait_lifecycle(&runtime, directory.path(), 1).await;
        check(&start[0], "start", port, started.elapsed());
        // No origin or client tunnel data was sent before the start check.
        peer.write_all(b"server-first").await.unwrap();
        let mut banner = [0; 12];
        timeout(LIMIT, client.read_exact(&mut banner))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&banner, b"server-first");
        if server_half_first {
            peer.shutdown().await.unwrap();
            assert!(remaining(&mut client).await.is_empty());
            assert_eq!(lifecycle(&runtime, directory.path()), start);
            client.write_all(b"after-server-eof").await.unwrap();
            client.shutdown().await.unwrap();
            assert_eq!(remaining(&mut peer).await, b"after-server-eof");
        } else {
            client.write_all(b"before-client-eof").await.unwrap();
            client.shutdown().await.unwrap();
            assert_eq!(remaining(&mut peer).await, b"before-client-eof");
            assert_eq!(lifecycle(&runtime, directory.path()), start);
            peer.write_all(b"after-client-eof").await.unwrap();
            peer.shutdown().await.unwrap();
            assert_eq!(remaining(&mut client).await, b"after-client-eof");
        }
        drop(client);
        drop(peer);
        let rows = wait_lifecycle(&runtime, directory.path(), 2).await;
        assert_eq!(rows[0], start[0]);
        check(&rows[1], "end", port, started.elapsed());
        proxy.shutdown().await;
        assert_eq!(lifecycle(&runtime, directory.path()), rows);
        clean(directory.path());
    }
}

#[tokio::test]
async fn refused_owned_endpoint_emits_only_connect_error() {
    let directory = tempfile::tempdir().unwrap();
    let origin = listener().await;
    let port = origin.local_addr().unwrap().port();
    drop(origin);
    let proxy = Proxy::start(config(directory.path(), port, true, true))
        .await
        .unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let started = Instant::now();
    let (client, head) = request(directory.path(), port).await;
    assert!(head.starts_with(b"HTTP/1.1 502"));
    drop(client);
    let rows = wait_lifecycle(&runtime, directory.path(), 1).await;
    assert!(
        rows[0]["details"]["error"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase()
            .contains("refused")
    );
    check(&rows[0], "error", port, started.elapsed());
    proxy.shutdown().await;
    assert_eq!(lifecycle(&runtime, directory.path()), rows);
    clean(directory.path());
}

#[tokio::test]
async fn unmatched_opaque_and_policy_denial_do_not_create_logger_sessions() {
    for allowed in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let origin = listener().await;
        let port = origin.local_addr().unwrap().port();
        let proxy = Proxy::start(config(directory.path(), port, !allowed, allowed))
            .await
            .unwrap();
        let runtime = proxy.runtime.read().unwrap().clone();
        let (mut client, head) = request(directory.path(), port).await;
        if allowed {
            assert!(head.starts_with(b"HTTP/1.1 200"));
            let mut peer = accept(&origin).await;
            peer.write_all(b"owned-opaque").await.unwrap();
            peer.shutdown().await.unwrap();
            assert_eq!(remaining(&mut client).await, b"owned-opaque");
            client.write_all(b"reply").await.unwrap();
            client.shutdown().await.unwrap();
            assert_eq!(remaining(&mut peer).await, b"reply");
        } else {
            assert!(head.starts_with(b"HTTP/1.1 403"));
            assert!(
                !records(directory.path(), "events.jsonl")
                    .iter()
                    .any(|row| row["event"] == "proxy.egress")
            );
        }
        drop(client);
        proxy.shutdown().await;
        assert!(lifecycle(&runtime, directory.path()).is_empty());
        clean(directory.path());
    }
}

#[tokio::test]
async fn reload_retains_live_session_but_removal_applies_to_next_connection() {
    let directory = tempfile::tempdir().unwrap();
    let origin = listener().await;
    let port = origin.local_addr().unwrap().port();
    let mut configuration = config(directory.path(), port, true, true);
    let mut proxy = Proxy::start(configuration.clone()).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let started = Instant::now();
    let mut first = connect(directory.path(), port).await;
    let mut first_peer = accept(&origin).await;
    let start = wait_lifecycle(&runtime, directory.path(), 1).await;
    check(&start[0], "start", port, started.elapsed());
    configuration.ignore_hosts.clear();
    proxy.reload(configuration).await.unwrap();
    first_peer.write_all(b"live-after-reload").await.unwrap();
    first_peer.shutdown().await.unwrap();
    assert_eq!(remaining(&mut first).await, b"live-after-reload");
    assert_eq!(lifecycle(&runtime, directory.path()), start);
    first.write_all(b"still-open").await.unwrap();
    first.shutdown().await.unwrap();
    assert_eq!(remaining(&mut first_peer).await, b"still-open");
    drop(first);
    drop(first_peer);
    let first_rows = wait_lifecycle(&runtime, directory.path(), 2).await;
    check(&first_rows[1], "end", port, started.elapsed());
    let mut second = connect(directory.path(), port).await;
    let mut second_peer = accept(&origin).await;
    second_peer.write_all(b"unmatched-now").await.unwrap();
    second_peer.shutdown().await.unwrap();
    assert_eq!(remaining(&mut second).await, b"unmatched-now");
    second.shutdown().await.unwrap();
    assert!(remaining(&mut second_peer).await.is_empty());
    drop(second);
    drop(second_peer);
    proxy.shutdown().await;
    assert_eq!(lifecycle(&runtime, directory.path()), first_rows);
    clean(directory.path());
}

#[tokio::test]
async fn graceful_shutdown_closes_live_transport_then_emits_end() {
    let directory = tempfile::tempdir().unwrap();
    let origin = listener().await;
    let port = origin.local_addr().unwrap().port();
    let proxy = Proxy::start(config(directory.path(), port, true, true))
        .await
        .unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let started = Instant::now();
    let mut client = connect(directory.path(), port).await;
    let mut peer = accept(&origin).await;
    let start = wait_lifecycle(&runtime, directory.path(), 1).await;
    check(&start[0], "start", port, started.elapsed());
    timeout(LIMIT, proxy.shutdown()).await.unwrap();
    assert!(remaining(&mut client).await.is_empty());
    assert!(remaining(&mut peer).await.is_empty());
    let rows = lifecycle(&runtime, directory.path());
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0], start[0]);
    check(&rows[1], "end", port, started.elapsed());
    clean(directory.path());
}

#[tokio::test]
async fn connected_stream_cleanup_and_poisoned_writer_preserve_admitted_transport() {
    use super::{AllowedRequest, Destination, open_egress};
    use crate::{ConnectionIdentity, ignored_host_logger::SelectedDestination};

    // This calls the already-admitted egress seam deliberately. Poisoning the
    // normal CONNECT request first would hit NetworkGuard's earlier allow audit.
    // No earlier network gate is disabled or rewritten for this control.
    for poisoned in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let origin = listener().await;
        let port = origin.local_addr().unwrap().port();
        let proxy = Proxy::start(config(directory.path(), port, true, true))
            .await
            .unwrap();
        let runtime = proxy.runtime.read().unwrap().clone();
        let identity = ConnectionIdentity {
            agent_id: "alice".into(),
            connection_id: "owned-lifecycle-seam".into(),
            source_id: Some(SOURCE.into()),
        };
        let request = hyper::Request::builder()
            .method("CONNECT")
            .uri(format!("{HOST}:{port}"))
            .body(())
            .unwrap();
        let destination = Destination::from_request(&request, None).unwrap();
        // Startup precedes the synthetic writer failure. No later event may
        // be appended after poisoning, including a tunnel lifecycle event.
        assert!(runtime.audit.wait_for_drain(LIMIT).unwrap());
        let before = records(directory.path(), "audit.jsonl");
        assert_eq!(before.len(), 1);
        assert_eq!(before[0]["addon"], "memory-monitor");
        assert_eq!(before[0]["event"], "ops.startup");
        if poisoned {
            runtime.audit.poison_for_test();
        }
        let started = Instant::now();
        let connected = timeout(
            LIMIT,
            open_egress(
                &runtime,
                &AllowedRequest {
                    tasks: &crate::connection_tasks::ConnectionTasks::new(
                        tokio::sync::watch::channel(false).1,
                    ),
                    destination: &destination,
                    identity: &identity,
                    request_id: "req-11111111111111111111111111111111",
                },
                true,
                Some(SelectedDestination { host: HOST, port }),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        let mut peer = accept(&origin).await;
        if poisoned {
            let (mut client, proxy_side) = UnixStream::pair().unwrap();
            let (_stop, receiver) = tokio::sync::watch::channel(false);
            let relay = tokio::spawn(crate::tunnels::relay(
                Box::new(proxy_side),
                connected.stream,
                receiver,
            ));
            peer.write_all(b"poisoned-sink").await.unwrap();
            peer.shutdown().await.unwrap();
            assert_eq!(remaining(&mut client).await, b"poisoned-sink");
            client.write_all(b"still-admitted").await.unwrap();
            client.shutdown().await.unwrap();
            assert_eq!(remaining(&mut peer).await, b"still-admitted");
            let outcome = timeout(LIMIT, relay).await.unwrap().unwrap();
            assert_eq!(outcome.outcome, "completed");
            assert_eq!((outcome.uploaded, outcome.downloaded), (14, 13));
            assert_eq!(
                runtime.audit.shutdown(LIMIT).unwrap_err().kind(),
                crate::audit::ErrorKind::Poisoned
            );
            assert_eq!(records(directory.path(), "audit.jsonl"), before);
        } else {
            let start = wait_lifecycle(&runtime, directory.path(), 1).await;
            check(&start[0], "start", port, started.elapsed());
            // No client upgrade future or relay has been created. Dropping this
            // connected owner must close TCP and consume its terminal event.
            drop(connected.stream);
            assert!(remaining(&mut peer).await.is_empty());
            let rows = wait_lifecycle(&runtime, directory.path(), 2).await;
            assert_eq!(rows[0], start[0]);
            check(&rows[1], "end", port, started.elapsed());
        }
        drop(peer);
        proxy.shutdown().await;
        clean(directory.path());
    }
}

#[test]
fn pending_guard_drop_or_explicit_error_consumes_terminal_ownership_once() {
    use super::ignored_host::ConnectionAudit;
    use crate::{ConnectionIdentity, audit, ignored_host_logger::SelectedDestination};
    use std::sync::Arc;

    // In-memory bookkeeping only: no pending TCP connection is created, and
    // this does not claim equivalence to every source cancellation phase.
    let directory = tempfile::tempdir().unwrap();
    let writer = Arc::new(audit::Writer::new(
        directory.path().join("audit.jsonl"),
        audit::Settings::default(),
    ));
    let identity = ConnectionIdentity {
        agent_id: "alice".into(),
        connection_id: "owned-pending-seam".into(),
        source_id: Some(SOURCE.into()),
    };
    let selected = || SelectedDestination {
        host: HOST,
        port: 443,
    };
    drop(ConnectionAudit::new(writer.clone(), &identity, selected()));
    let first = writer_lifecycle(&writer, directory.path());
    assert_eq!(first.len(), 1);
    assert_eq!(first[0]["details"]["error"], "connection cancelled");
    check(&first[0], "error", 443, Duration::ZERO);
    let mut explicit = ConnectionAudit::new(writer.clone(), &identity, selected());
    explicit.failed("owned explicit connection failure");
    let before_drop = writer_lifecycle(&writer, directory.path());
    assert_eq!(before_drop.len(), 2);
    assert_eq!(before_drop[0], first[0]);
    assert_eq!(
        before_drop[1]["details"]["error"],
        "owned explicit connection failure"
    );
    check(&before_drop[1], "error", 443, Duration::ZERO);
    drop(explicit);
    assert_eq!(writer_lifecycle(&writer, directory.path()), before_drop);
    assert!(writer.shutdown(LIMIT).unwrap());
}
