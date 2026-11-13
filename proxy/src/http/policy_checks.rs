//! Named-check admission at the existing transport boundaries.
use super::*;
use crate::policy::checks::{self, Action, Stage};

#[derive(Debug)]
pub(super) struct Denied {
    action: Action,
    explanation: serde_json::Value,
}
impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("named policy check refused the operation")
    }
}
impl std::error::Error for Denied {}
impl Denied {
    pub(super) fn response(&self) -> Response<Body> {
        let status = match self.action {
            Action::Approval => 428,
            Action::Unresolved => 503,
            _ => 403,
        };
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .header("x-blocked-by", "policy-checks")
            .body(full(
                json!({"action":self.action,"checks":self.explanation,"next_action":if self.action==Action::Approval {Some("review the named rule and apply an explicit scoped exception or revised policy")}else{None}}).to_string(),
            ))
            .unwrap()
    }
}

pub(super) fn current(
    runtime: &Runtime,
    state: &RuntimeState,
    identity: &ConnectionIdentity,
) -> Result<(), Error> {
    if runtime
        .policy
        .as_ref()
        .is_none_or(|policy| policy.named_checks().rules.is_empty())
    {
        return Ok(());
    }
    let current = state.read().map_err(|_| "current policy unavailable")?;
    if match (&runtime.policy, &current.policy) {
        (Some(expected), Some(actual)) => !Arc::ptr_eq(expected, actual),
        (None, None) => false,
        _ => true,
    } || identity.current_agent_run().is_some_and(|run| {
        current
            .policy
            .as_ref()
            .is_none_or(|policy| !run.current(policy))
    }) {
        return Err(Denied {action:Action::Unresolved,explanation:json!({"reason":"policy or authority changed while evidence was pending; retry under current authority"})}.into());
    }
    Ok(())
}

pub(super) async fn enforce(
    runtime: &Runtime,
    state: &RuntimeState,
    identity: &ConnectionIdentity,
    request_id: &str,
    stage: Stage,
    request: &checks::Request<'_>,
) -> Result<(), Error> {
    let Some(policy) = runtime.policy.as_ref() else {
        return Ok(());
    };
    if !policy.named_checks().applies(request, stage) {
        return Ok(());
    }
    current(runtime, state, identity)?;
    let evidence = policy.named_checks().collect(request, stage).await?;
    if !policy.named_checks().versions_current(&evidence).await {
        return Err(Denied {action:Action::Unresolved,explanation:json!({"reason":"evidence version changed while the check was pending; retry against the current snapshot"})}.into());
    }

    // No runtime lock survives an evidence wait. A completed lookup cannot
    // restore superseded permission, even if its finding would allow access.
    current(runtime, state, identity)?;
    let result = policy.named_checks().evaluate(
        request,
        stage,
        evidence,
        crate::policy::current_time_ms() as u64,
    );
    runtime.audit.emit(identity.request_event(
        "security.network_guard.evaluated",
        crate::audit::Kind::Security,
        request_id,
        "Named policy checks evaluated",
        json!({"control":"network","named_checks":result}),
    ))?;
    if result.action != Action::Allow {
        return Err(Denied {
            action: result.action,
            explanation: serde_json::to_value(result)?,
        }
        .into());
    }
    Ok(())
}

pub(super) fn request<'a>(
    identity: &'a ConnectionIdentity,
    destination: &'a Destination,
    method: &'a str,
    ip: Option<std::net::IpAddr>,
    visible: bool,
) -> checks::Request<'a> {
    checks::Request {
        agent: identity.request_agent(),
        host: &destination.policy_host,
        port: destination.port,
        scheme: &destination.scheme,
        method,
        path: visible.then_some(destination.path.as_str()),
        ip,
        value: None,
    }
}

#[cfg(test)]
fn isolated_native_test(name: &str) -> bool {
    const CHILD: &str = "SAFEYOLO_NAMED_CHECKS_NATIVE_TEST";
    if std::env::var(CHILD).as_deref() == Ok(name) {
        return false;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env(CHILD, name)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    true
}

#[cfg(test)]
fn test_policy(
    directory: &std::path::Path,
    checks: serde_json::Value,
    rules: Vec<serde_json::Value>,
) {
    // Serialize typed numbers: serde_json's arbitrary-precision representation
    // is a JSON format contract, not a TOML integer representation.
    let checks: checks::Checks =
        serde_json::from_value(json!({"checks":checks,"check_rules":rules})).unwrap();
    let source = format!(
        "[hosts.'*']\negress='allow'\n[agents.alice.hosts.'*']\negress='allow'\n[controls.network]\nhomoglyph=false\n[controls.circuits]\nenabled=false\n{}",
        toml::to_string(&checks).unwrap()
    );
    std::fs::write(directory.join("policy.toml"), source).unwrap();
}

#[cfg(test)]
fn test_configuration(directory: &std::path::Path, source: &str) -> crate::Config {
    for path in ["data", "logs", "services", "builtin-services"] {
        std::fs::create_dir_all(directory.join(path)).unwrap();
    }
    for (path, value) in [
        ("data/admin_token", "synthetic-named-check-admin-token"),
        ("data/agent_token", "synthetic-named-check-agent-token"),
        ("data/instance_id", "sy-dddddddddddddddddddddddddddddddd"),
    ] {
        std::fs::write(directory.join(path), value).unwrap();
    }
    let path = directory.join("config.toml");
    std::fs::write(&path, source).unwrap();
    crate::native_config::read(&path).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Proxy,
        policy::checks::{Check, CheckResult, Finding, Provenance, Subject},
    };
    use std::{path::Path, sync::atomic::AtomicUsize};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
        time::timeout,
    };
    const LIMIT: Duration = Duration::from_secs(10);

    fn check(path: &Path, subject: &str) -> serde_json::Value {
        json!({"source_id":"controlled-provider","meaning":"controlled fixture membership","subject":subject,"result_type":"finding","influences":["hard_exclusion"],"implementation_version":"fixture-1","configuration_version":"selected-1","max_age_seconds":60,"source":{"kind":"recorded","path":path}})
    }
    fn rule(name: &str, stage: &str, check: &str, fallback: &str) -> serde_json::Value {
        json!({"name":name,"host":"*","stage":stage,"influence":"hard_exclusion","priority":0,"required":true,"when":{"op":"finding","check":check},"on_match":"deny","on_unavailable":fallback})
    }
    fn record(check: &serde_json::Value, subject: Subject, positive: bool) -> CheckResult {
        let check: Check = serde_json::from_value(check.clone()).unwrap();
        CheckResult {
            input_digest: check.input_digest(&subject).unwrap(),
            subject,
            implementation_version: check.implementation_version,
            configuration_version: check.configuration_version,
            collected_at_ms: crate::policy::current_time_ms() as u64,
            valid_until_ms: None,
            source: Provenance {
                source_id: check.source_id,
                source_revision: Some("fixture-capture-1".into()),
                content_digest: None,
                source_observed_at_ms: None,
            },
            finding: Finding::Finding { positive },
        }
    }
    fn write_records(path: &Path, records: &[CheckResult]) {
        std::fs::write(path, serde_json::to_vec(records).unwrap()).unwrap();
    }
    fn config(directory: &Path, parent: Option<std::net::SocketAddr>) -> crate::Config {
        let mut source =
            "admin_port=0\nflow_store_enabled=false\ncircuit_state_file=''\n".to_owned();
        if let Some(parent) = parent {
            source.push_str(&format!("parent_proxy='http://{parent}'\n"));
        }
        source.push_str("[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n");
        test_configuration(directory, &source)
    }
    async fn get(directory: &Path, address: std::net::SocketAddr, path: &str) -> Vec<u8> {
        get_authority(directory, &address.to_string(), path).await
    }
    async fn get_authority(directory: &Path, authority: &str, path: &str) -> Vec<u8> {
        let mut stream = UnixStream::connect(directory.join("alice.sock"))
            .await
            .unwrap();
        stream.write_all(format!("GET http://{authority}{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut reply = Vec::new();
        timeout(LIMIT, stream.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        reply
    }
    async fn origin(
        ip: &str,
    ) -> (
        std::net::SocketAddr,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        let (listener, address) = crate::test_owned_endpoint::bind_on(ip.parse().unwrap()).await;
        let contacts = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let accepted = contacts.clone();
        let received = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                accepted.fetch_add(1, Ordering::SeqCst);
                let received = received.clone();
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        match stream.read_u8().await {
                            Ok(byte) => head.push(byte),
                            Err(_) => return,
                        }
                    }
                    received.fetch_add(1, Ordering::SeqCst);
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await
                        .unwrap();
                });
            }
        });
        (address, contacts, requests, task)
    }

    #[tokio::test]
    async fn native_scoped_ipv6_preserves_exclusions_and_request_fallback() {
        if isolated_native_test(
            "http::policy_checks::tests::native_scoped_ipv6_preserves_exclusions_and_request_fallback",
        ) {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let (address, contacts, requests, origin) = origin("::1").await;
        let ip_file = root.join("ip.json");
        let host_file = root.join("hostname.json");
        let ip = check(&ip_file, "ip");
        let host = check(&host_file, "hostname");
        let subject = Subject::Ip {
            address: address.ip(),
        };
        write_records(&ip_file, &[record(&ip, subject.clone(), true)]);
        test_policy(
            root,
            json!({"ip":ip,"hostname":host}),
            vec![
                rule("never", "connect", "ip", "unresolved"),
                rule("direct-ip", "request", "hostname", "unresolved"),
            ],
        );
        let configuration = config(root, None);
        let mut proxy = Proxy::start(configuration.clone()).await.unwrap();
        let authorities = [address.to_string(), format!("[::1%0]:{}", address.port())];
        for authority in &authorities {
            let reply = get_authority(root, authority, "/").await;
            assert!(
                reply.starts_with(b"HTTP/1.1 403"),
                "{}",
                String::from_utf8_lossy(&reply)
            );
            assert_eq!(contacts.load(Ordering::SeqCst), 0, "{authority}");
        }
        write_records(&ip_file, &[record(&ip, subject, false)]);
        for authority in &authorities {
            let reply = get_authority(root, authority, "/").await;
            assert!(
                reply.starts_with(b"HTTP/1.1 503"),
                "{}",
                String::from_utf8_lossy(&reply)
            );
            assert!(String::from_utf8_lossy(&reply).contains("direct-ip"));
            assert_eq!(requests.load(Ordering::SeqCst), 0, "{authority}");
        }
        // Scoped spelling remains usable when the operator selects continue.
        test_policy(
            root,
            json!({"ip":ip,"hostname":host}),
            vec![
                rule("never", "connect", "ip", "unresolved"),
                rule("direct-ip", "request", "hostname", "continue"),
            ],
        );
        proxy.reload(configuration.clone()).await.unwrap();
        for authority in &authorities {
            let reply = get_authority(root, authority, "/").await;
            assert!(
                reply.starts_with(b"HTTP/1.1 200"),
                "{}",
                String::from_utf8_lossy(&reply)
            );
        }
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        let path = check(&root.join("path.json"), "http_path");
        for fallback in ["unresolved", "continue"] {
            test_policy(
                root,
                json!({"ip":ip,"path":path}),
                vec![
                    rule("never", "connect", "ip", "unresolved"),
                    rule("visible-path", "request", "path", fallback),
                ],
            );
            proxy.reload(configuration.clone()).await.unwrap();
            for authority in &authorities {
                let mut client = UnixStream::connect(root.join("alice.sock")).await.unwrap();
                client
                    .write_all(
                        format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n")
                            .as_bytes(),
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
                assert!(
                    head.starts_with(b"HTTP/1.1 200"),
                    "{}",
                    String::from_utf8_lossy(&head)
                );
                // A NUL selects opaque framing; a token followed by CRLF is
                // deliberately retained on the inspected HTTP parser path.
                client.write_all(b"\0opaque-fixture\r\n\r\n").await.unwrap();
                client.shutdown().await.unwrap();
                let mut reply = Vec::new();
                let result = timeout(LIMIT, client.read_to_end(&mut reply))
                    .await
                    .unwrap();
                if fallback == "unresolved" {
                    assert!(
                        result.is_ok()
                            || result.unwrap_err().kind() == std::io::ErrorKind::ConnectionReset
                    );
                    assert!(reply.is_empty(), "opaque request must not reach the origin");
                    assert_eq!(requests.load(Ordering::SeqCst), 2);
                } else {
                    result.unwrap();
                    assert!(
                        reply.starts_with(b"HTTP/1.1 200"),
                        "{}",
                        String::from_utf8_lossy(&reply)
                    );
                }
            }
        }
        assert_eq!(requests.load(Ordering::SeqCst), 4);
        proxy.shutdown().await;
        origin.abort();
    }

    #[tokio::test]
    async fn native_named_checks_prevent_connect_and_forward_and_recover_from_bad_evidence() {
        if isolated_native_test(
            "http::policy_checks::tests::native_named_checks_prevent_connect_and_forward_and_recover_from_bad_evidence",
        ) {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let (address, contacts, requests, origin) = origin("127.0.0.2").await;
        let ip_file = root.join("ip.json");
        let path_file = root.join("path.json");
        let ip = check(&ip_file, "ip");
        let path_check = check(&path_file, "http_path");
        let ip_subject = Subject::Ip {
            address: address.ip(),
        };
        let path_subject = |path: &str| Subject::HttpPath {
            hostname: address.ip().to_string(),
            port: address.port(),
            scheme: "http".into(),
            method: "GET".into(),
            path: path.into(),
        };
        write_records(&ip_file, &[record(&ip, ip_subject.clone(), true)]);
        write_records(
            &path_file,
            &[
                record(&path_check, path_subject("/allowed"), false),
                record(&path_check, path_subject("/blocked"), true),
            ],
        );
        test_policy(
            root,
            json!({"ip":ip,"path":path_check}),
            vec![
                rule("never", "connect", "ip", "unresolved"),
                rule("path", "request", "path", "continue"),
            ],
        );
        let proxy = Proxy::start(config(root, None)).await.unwrap();
        let denied = get(root, address, "/allowed").await;
        assert!(
            denied.starts_with(b"HTTP/1.1 403"),
            "{}",
            String::from_utf8_lossy(&denied)
        );
        assert_eq!(
            contacts.load(Ordering::SeqCst),
            0,
            "IP denial precedes the actual connect"
        );
        let active = proxy.runtime.read().unwrap().policy.clone().unwrap();
        let preview = active
            .evaluate_candidate(&checks::Request {
                agent: Some("alice"),
                host: "127.0.0.2",
                port: address.port(),
                scheme: "http",
                method: "GET",
                path: Some("/allowed"),
                ip: Some(address.ip()),
                value: None,
            })
            .await
            .unwrap();
        assert_eq!(preview["action"], "deny");
        assert_eq!(
            contacts.load(Ordering::SeqCst),
            0,
            "preview makes no direct or dependency contact"
        );
        write_records(&ip_file, &[record(&ip, ip_subject.clone(), false)]);
        assert!(
            get(root, address, "/blocked")
                .await
                .starts_with(b"HTTP/1.1 403")
        );
        assert_eq!(
            requests.load(Ordering::SeqCst),
            0,
            "visible path denial precedes forwarding"
        );
        assert!(
            get(root, address, "/allowed?query=not-a-path-input")
                .await
                .starts_with(b"HTTP/1.1 200")
        );
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        std::fs::write(&ip_file, b"malformed provider output").unwrap();
        assert!(
            get(root, address, "/allowed")
                .await
                .starts_with(b"HTTP/1.1 503")
        );
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        let mut stale = record(&ip, ip_subject.clone(), false);
        stale.valid_until_ms = Some(1);
        write_records(&ip_file, &[stale]);
        assert!(
            get(root, address, "/allowed")
                .await
                .starts_with(b"HTTP/1.1 503")
        );
        write_records(&ip_file, &[record(&ip, ip_subject, false)]);
        assert!(
            get(root, address, "/allowed")
                .await
                .starts_with(b"HTTP/1.1 200")
        );
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        proxy.shutdown().await;
        origin.abort();
    }

    #[tokio::test]
    async fn hidden_origin_endpoint_uses_explicit_fallback_before_contacting_parent() {
        if isolated_native_test(
            "http::policy_checks::tests::hidden_origin_endpoint_uses_explicit_fallback_before_contacting_parent",
        ) {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let (parent, contacts, _, origin) = origin("127.0.0.2").await;
        let file = root.join("ip.json");
        let ip = check(&file, "ip");
        write_records(
            &file,
            &[record(
                &ip,
                Subject::Ip {
                    address: "192.0.2.17".parse().unwrap(),
                },
                false,
            )],
        );
        test_policy(
            root,
            json!({"ip":ip}),
            vec![rule("required-endpoint", "connect", "ip", "unresolved")],
        );
        let proxy = Proxy::start(config(root, Some(parent))).await.unwrap();
        let response = get(root, "192.0.2.17:80".parse().unwrap(), "/").await;
        assert!(
            response.starts_with(b"HTTP/1.1 503"),
            "{}",
            String::from_utf8_lossy(&response)
        );
        assert_eq!(contacts.load(Ordering::SeqCst), 0);
        proxy.shutdown().await;
        origin.abort();
    }

    #[tokio::test]
    async fn delayed_captured_provider_response_cannot_restore_revoked_policy() {
        if isolated_native_test(
            "http::policy_checks::tests::delayed_captured_provider_response_cannot_restore_revoked_policy",
        ) {
            return;
        }
        use std::{ffi::CString, os::unix::fs::OpenOptionsExt};
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let (address, contacts, _, origin) = origin("127.0.0.2").await;
        let file = root.join("held-provider.json");
        let name = CString::new(file.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let ip = check(&file, "ip");
        test_policy(
            root,
            json!({"ip":ip}),
            vec![rule("held", "connect", "ip", "unresolved")],
        );
        let configuration = config(root, None);
        let mut proxy = Proxy::start(configuration.clone()).await.unwrap();
        let task = {
            let root = root.to_owned();
            tokio::spawn(async move { get(&root, address, "/").await })
        };
        // O_NONBLOCK opens only after the production evidence reader is waiting.
        let mut writer = timeout(LIMIT, async {
            loop {
                match std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(&file)
                {
                    Ok(writer) => break writer,
                    Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {
                        tokio::task::yield_now().await
                    }
                    Err(error) => panic!("held provider setup failed: {error}"),
                }
            }
        })
        .await
        .unwrap();
        let revoked = "[hosts.'*']\negress='deny'\n[controls.circuits]\nenabled=false\n";
        std::fs::write(root.join("policy.toml"), revoked).unwrap();
        proxy.reload(configuration).await.unwrap();
        let record = record(
            &ip,
            Subject::Ip {
                address: address.ip(),
            },
            false,
        );
        std::io::Write::write_all(&mut writer, &serde_json::to_vec(&vec![record]).unwrap())
            .unwrap();
        drop(writer);
        let response = timeout(LIMIT, task).await.unwrap().unwrap();
        assert!(
            response.starts_with(b"HTTP/1.1 503"),
            "{}",
            String::from_utf8_lossy(&response)
        );
        assert_eq!(
            contacts.load(Ordering::SeqCst),
            0,
            "late favorable evidence cannot restore revoked authority"
        );
        proxy.shutdown().await;
        origin.abort();
    }
}

#[cfg(test)]
mod redirect_tests {
    use super::*;
    use crate::{
        Proxy,
        policy::checks::{Check, CheckResult, Finding, Provenance, Subject},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
        time::timeout,
    };
    #[tokio::test]
    async fn redirected_destination_requires_its_own_endpoint_evidence() {
        if isolated_native_test(
            "http::policy_checks::redirect_tests::redirected_destination_requires_its_own_endpoint_evidence",
        ) {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let (first, address) =
            crate::test_owned_endpoint::bind_on("127.0.0.2".parse().unwrap()).await;
        let (blocked, other) =
            crate::test_owned_endpoint::bind_on("127.0.0.3".parse().unwrap()).await;
        let file = root.join("results.json");
        let definition = json!({"source_id":"redirect-fixture","meaning":"controlled IP exclusion","subject":"ip","result_type":"finding","influences":["hard_exclusion"],"implementation_version":"fixture-1","configuration_version":"config-1","max_age_seconds":60,"source":{"kind":"recorded","path":file}});
        let check: Check = serde_json::from_value(definition.clone()).unwrap();
        let mut records = Vec::new();
        for (ip, positive) in [(address.ip(), false), (other.ip(), true)] {
            let subject = Subject::Ip { address: ip };
            records.push(CheckResult {
                input_digest: check.input_digest(&subject).unwrap(),
                subject,
                implementation_version: check.implementation_version.clone(),
                configuration_version: check.configuration_version.clone(),
                collected_at_ms: crate::policy::current_time_ms() as u64,
                valid_until_ms: None,
                source: Provenance {
                    source_id: check.source_id.clone(),
                    source_revision: Some("fixture-1".into()),
                    content_digest: None,
                    source_observed_at_ms: None,
                },
                finding: Finding::Finding { positive },
            });
        }
        std::fs::write(&file, serde_json::to_vec(&records).unwrap()).unwrap();
        test_policy(
            root,
            json!({"ip":definition}),
            vec![
                json!({"name":"never","host":"*","stage":"connect","influence":"hard_exclusion","priority":0,"required":true,"when":{"op":"finding","check":"ip"},"on_match":"deny","on_unavailable":"unresolved"}),
            ],
        );
        let config = test_configuration(
            root,
            "admin_port=0\nflow_store_enabled=false\ncircuit_state_file=''\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n",
        );
        let proxy = Proxy::start(config).await.unwrap();
        let redirect = tokio::spawn(async move {
            let (mut stream, _) = first.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await.unwrap());
            }
            stream.write_all(format!("HTTP/1.1 302 Found\r\nLocation: http://{other}/changed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        });
        for (target, status) in [(address, "302"), (other, "403")] {
            let mut client = UnixStream::connect(root.join("alice.sock")).await.unwrap();
            client.write_all(format!("GET http://{target}/changed HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            let mut reply = Vec::new();
            timeout(Duration::from_secs(5), client.read_to_end(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert!(
                String::from_utf8_lossy(&reply).starts_with(&format!("HTTP/1.1 {status}")),
                "{}",
                String::from_utf8_lossy(&reply)
            );
        }
        assert!(
            timeout(Duration::from_millis(20), blocked.accept())
                .await
                .is_err(),
            "redirect did not authorize contact with another endpoint"
        );
        redirect.await.unwrap();
        proxy.shutdown().await;
    }
}
