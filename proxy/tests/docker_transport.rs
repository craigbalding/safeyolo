//! Real proxy-wire tests. The small origin controls protocol failures; it is
//! not a Docker daemon and does not establish Docker/Compose lifecycle support.
use safeyolo_proxy::credentials::{Credential, Secret};
use safeyolo_proxy::{Config, Proxy, http_content::BUFFERED_BODY_THRESHOLD};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixStream},
    time::timeout,
};

const LIMIT: Duration = Duration::from_secs(15);
const ORIGIN_CREDENTIAL: &str = "synthetic-operator-held-docker-credential";

#[test]
fn docker_endpoint_is_a_fixed_origin_and_template_loads() {
    let mut template = safeyolo_proxy::services::ServiceDefinition::from_yaml(include_str!(
        "../../contrib/docker/service.yaml"
    ))
    .unwrap()
    .raw;
    for endpoint in [
        "ssh://host",
        "https://user:secret@host",
        "https://host/path",
        "https://host/?query=value",
        "https://host:999999",
    ] {
        template["docker"]["endpoint"] = json!(endpoint);
        assert!(
            safeyolo_proxy::services::ServiceDefinition::from_value(template.clone()).is_err(),
            "{endpoint}"
        );
    }
}

fn service(port: u16) -> Value {
    json!({"schema_version":1,"name":"docker-test","docker":{"endpoint":format!("http://127.0.0.1:{port}"),"execution_boundary":"sandbox"},
        "capabilities":{"engine":{"docker_access":{"mode":"sandbox_admin"},"routes":[{"methods":["GET","HEAD","POST","PUT","DELETE"],"path":"/v1.45/**"}]}}})
}

async fn start(root: &Path, definition: Value, deny_create: bool, scan_body: bool) -> Proxy {
    std::fs::create_dir(root.join("builtin")).unwrap();
    std::fs::create_dir(root.join("services")).unwrap();
    std::fs::write(root.join("services/docker.yaml"), definition.to_string()).unwrap();
    let endpoint: hyper::Uri = definition["docker"]["endpoint"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let mut permissions = json!([
        {"action":"network:request","resource":"*","effect":"allow"},
        {"action":"credential:use","resource":"*","effect":"allow"},
        {"action":"gateway:request","resource":"docker-test:*","effect":"allow"}
    ]);
    if deny_create {
        permissions.as_array_mut().unwrap().insert(0, json!({"action":"gateway:request","resource":"docker-test:/v1.45/containers/create","effect":"deny"}));
    }
    let mut policy = json!({"permissions":permissions,"gateway":{"host_map":{endpoint.host().unwrap():"docker-test"},
        "token_map":{"sgw_alice":{"agent":"alice","service":"docker-test","capability":"engine","token":"unused","account":"test"}}}});
    if scan_body {
        policy["scan_patterns"] = json!([{"name":"required-body","pattern":"forbidden","scope":["body"],"target":"request","action":"block"}]);
    }
    std::fs::write(root.join("policy.json"), policy.to_string()).unwrap();
    let mut config: Config = serde_json::from_value(json!({
        "listeners":[{"agent_id":"alice","socket_path":root.join("alice.sock")},{"agent_id":"bob","socket_path":root.join("bob.sock")}],
        "policy_file":root.join("policy.json"),"gateway_builtin_services_dir":root.join("builtin"),
        "gateway_services_dir":root.join("services"),"data_dir":root.join("data"),"readiness_file":root.join("ready"),
        "audit_log_path":root.join("audit.jsonl"),"flow_store_enabled":false,"flow_store_db_path":root.join("flows.sqlite3"),
        "circuit_breaker_enabled":false,"circuit_state_file":"","ignore_hosts":["127.0.0.1"]
    })).unwrap();
    if scan_body {
        config.inspection = Some(safeyolo_proxy::Inspection {
            policy_file: root.join("policy.json"),
            block_request: true,
            block_response: false,
            block_websocket_request: false,
            block_websocket_response: false,
        });
    }
    if definition.get("auth").is_some() {
        let vault = safeyolo_proxy::credentials::open(&root.join("data")).unwrap();
        vault
            .store(Credential::new(
                "unused",
                "bearer",
                Secret::new(ORIGIN_CREDENTIAL),
            ))
            .unwrap();
    }
    if root.join("origin-ca.pem").exists() {
        config.upstream_ca_file = Some(root.join("origin-ca.pem"));
        config.tls_ca_file = Some(root.join("interception-ca.pem"));
    }
    Proxy::start(config).await.unwrap()
}

async fn head(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    timeout(LIMIT, async {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(stream.read_u8().await.unwrap());
            assert!(bytes.len() < 64 * 1024);
        }
        bytes
    })
    .await
    .unwrap()
}

fn request(method: &str, path: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("{method} {path} HTTP/1.1\r\nHost: proxy.invalid:3128\r\nContent-Length: {}\r\n{headers}\r\n",body.len()).into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

async fn call(root: &Path, agent: &str, bytes: &[u8]) -> Vec<u8> {
    timeout(LIMIT, async {
        let mut stream = UnixStream::connect(root.join(format!("{agent}.sock")))
            .await
            .unwrap();
        stream.write_all(bytes).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        response
    })
    .await
    .unwrap()
}

fn workloads(port: u16) -> Value {
    let mut definition = service(port);
    definition["docker"]["execution_boundary"] = json!("external");
    definition["capabilities"]["engine"]["docker_access"] =
        json!({"mode":"workloads","bind_mounts":[]});
    definition
}

#[tokio::test]
async fn forbidden_docker_arguments_and_forged_boundary_never_contact_the_origin() {
    let root = tempfile::tempdir().unwrap();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = start(
        root.path(),
        workloads(origin.local_addr().unwrap().port()),
        false,
        false,
    )
    .await;
    for host in [
        json!({"Privileged":true}),
        json!({"Binds":["/var/run/docker.sock:/socket"]}),
        json!({"Mounts":[{"Type":"volume","Target":"/host","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"device":"/","o":"bind","type":"none"}}}}]}),
    ] {
        let response=call(root.path(),"alice",&request("POST","/v1.45/containers/create","X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\nContent-Type: application/json\r\nX-SafeYolo-Execution-Boundary: sandbox\r\nConnection: close\r\n",&serde_json::to_vec(&json!({"Image":"busybox","HostConfig":host})).unwrap())).await;
        assert!(
            response.starts_with(b"HTTP/1.1 403"),
            "{}",
            String::from_utf8_lossy(&response)
        );
    }
    for body in [
        json!({"Cmd":["true"],"Detach":false,"ConsoleSize":[24,80],"Privileged":true}),
        json!({"Cmd":["true"],"Detach":"false"}),
        json!({"Cmd":["true"],"ConsoleSize":[24,-1]}),
        json!({"Cmd":["true"],"ConsoleSize":[24,"80"]}),
        json!({"Cmd":["true"],"Detach":false,"FutureOption":true}),
    ] {
        let response = call(
            root.path(),
            "alice",
            &request(
                "POST",
                "/v1.45/containers/existing/exec",
                "X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\nContent-Type: application/json\r\nConnection: close\r\n",
                &serde_json::to_vec(&body).unwrap(),
            ),
        )
        .await;
        assert!(response.starts_with(b"HTTP/1.1 403"));
    }
    let updates: Value =
        serde_json::from_str(include_str!("fixtures/docker/update-defaults.json")).unwrap();
    for change in [
        json!({"Privileged":true}),
        json!({"NetworkMode":"bridge"}),
        json!({"Binds":["/var/run/docker.sock:/socket"]}),
        json!({"CapAdd":["SYS_ADMIN"]}),
        json!({"CgroupParent":"/another-workload"}),
        json!({"Devices":[{"PathOnHost":"/dev/sda","PathInContainer":"/dev/sda","CgroupPermissions":"rwm"}]}),
        json!({"DeviceCgroupRules":["a *:* rwm"]}),
        json!({"DeviceRequests":[{"Driver":"nvidia","Count":-1,"Capabilities":[["gpu"]]}]}),
        json!({"MemorySwappiness":-2}),
        json!({"MemorySwappiness":101}),
        json!({"MemorySwappiness":"-1"}),
        json!({"Memory":-1}),
        json!({"RestartPolicy":{"Name":"unknown"}}),
        json!({"RestartPolicy":{"Name":"on-failure","MaximumRetryCount":"3"}}),
        json!({"NanoCpus":500000000.5}),
        json!({"FutureOption":true}),
    ] {
        let mut body = updates[0]["body"].clone();
        body.as_object_mut()
            .unwrap()
            .extend(change.as_object().unwrap().clone());
        let response = call(
            root.path(),
            "alice",
            &request(
                "POST",
                "/v1.45/containers/existing/update",
                "X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\nContent-Type: application/json\r\nConnection: close\r\n",
                &serde_json::to_vec(&body).unwrap(),
            ),
        )
        .await;
        assert!(response.starts_with(b"HTTP/1.1 403"), "{change}");
    }
    assert!(
        timeout(Duration::from_millis(100), origin.accept())
            .await
            .is_err()
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn docker_resource_inspection_precedes_mutation_and_pins_existing_container_names() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/docker/compose-exec-defaults.json")).unwrap();
    let attached = serde_json::to_vec(&fixtures[0]["create"]).unwrap();
    let terminal = serde_json::to_vec(&fixtures[2]["create"]).unwrap();
    for (safe, operation, body) in [
        (false, "start", b"".as_slice()),
        (true, "start", b"".as_slice()),
        (
            true,
            "rename?name=syproof21cd528538cf-web-1",
            b"".as_slice(),
        ),
        (
            false,
            "rename?name=syproof21cd528538cf-web-1",
            b"".as_slice(),
        ),
        (true, "exec", attached.as_slice()),
        (false, "exec", attached.as_slice()),
        (true, "exec", terminal.as_slice()),
        (false, "exec", terminal.as_slice()),
    ] {
        let root = tempfile::tempdir().unwrap();
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = start(
            root.path(),
            workloads(origin.local_addr().unwrap().port()),
            false,
            false,
        )
        .await;
        let expected_body = body.to_vec();
        let backend = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let headers = String::from_utf8(head(&mut stream).await).unwrap();
            assert!(
                headers.starts_with("GET /v1.45/containers/json/json HTTP/1.1"),
                "{headers}"
            );
            assert!(!headers.contains("sgw_"));
            let body=serde_json::to_vec(&json!({"Id":"d".repeat(64),"HostConfig":{"Privileged":!safe,"CgroupnsMode":"private","NetworkMode":"bridge"},"NetworkSettings":{"Networks":{}},"Mounts":[]})).unwrap();
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            stream.write_all(&body).await.unwrap();
            drop(stream);
            if safe {
                let (mut stream, _) = origin.accept().await.unwrap();
                let headers = String::from_utf8(head(&mut stream).await).unwrap();
                assert!(
                    headers.starts_with(&format!(
                        "POST /v1.45/containers/{}/{operation} HTTP/1.1",
                        "d".repeat(64)
                    )),
                    "{headers}"
                );
                let mut received_body = vec![0; expected_body.len()];
                stream.read_exact(&mut received_body).await.unwrap();
                assert_eq!(received_body, expected_body);
                let response = if operation == "exec" {
                    &b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"Id\":\"exec-1\"}"[..]
                } else {
                    &b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"[..]
                };
                stream.write_all(response).await.unwrap();
            } else {
                assert!(
                    timeout(Duration::from_millis(100), origin.accept())
                        .await
                        .is_err()
                );
            }
        });
        let response = call(
            root.path(),
            "alice",
            &request(
                "POST",
                &format!("/v1.45/containers/json/{operation}"),
                "X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\nContent-Type: application/json\r\nConnection: close\r\n",
                body,
            ),
        )
        .await;
        assert!(
            response.starts_with(if !safe {
                b"HTTP/1.1 403"
            } else if operation == "exec" {
                b"HTTP/1.1 201"
            } else {
                b"HTTP/1.1 204"
            }),
            "{}",
            String::from_utf8_lossy(&response)
        );
        timeout(LIMIT, backend).await.unwrap().unwrap();
        proxy.shutdown().await;
    }
}

fn events(root: &Path) -> Vec<Value> {
    std::fs::read_to_string(root.join("audit.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[tokio::test]
async fn fresh_resource_discovery_preserves_not_found_without_forwarding_unchecked_requests() {
    for project in [false, true] {
        for kind in ["networks", "volumes"] {
            for status in [404, 500, 200] {
                let root = tempfile::tempdir().unwrap();
                let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let mut definition = workloads(origin.local_addr().unwrap().port());
                if project {
                    definition["capabilities"]["engine"]["docker_access"] =
                        json!({"mode":"project","name":"alpha","adoption":"selection-1"});
                }
                let proxy = start(root.path(), definition, false, false).await;
                let path = format!("/v1.45/{kind}/ordinary");
                let expected = path.clone();
                let backend = tokio::spawn(async move {
                    let (mut stream, _) = origin.accept().await.unwrap();
                    let headers = String::from_utf8(head(&mut stream).await).unwrap();
                    assert!(headers.starts_with(&format!("GET {expected} HTTP/1.1")));
                    // An existing unsafe resource must still fail its checks.
                    // Its daemon error and configuration must not reach a project.
                    let body = json!({"Id":"b".repeat(64),"Name":"unrelated-workload","Driver":"host","Options":{"device":"/"},"message":"unrelated-workload exists"}).to_string();
                    stream.write_all(format!("HTTP/1.1 {status} Origin status\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
                    drop(stream);
                    assert!(
                        timeout(Duration::from_millis(100), origin.accept())
                            .await
                            .is_err()
                    );
                });
                let response = call(
                    root.path(),
                    "alice",
                    &request(
                        "GET",
                        &path,
                        "X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\nConnection: close\r\n",
                        b"",
                    ),
                )
                .await;
                let expected = if project || status == 404 {
                    "HTTP/1.1 404"
                } else {
                    "HTTP/1.1 403"
                };
                let response = String::from_utf8(response).unwrap();
                assert!(response.starts_with(expected), "{response}");
                assert!(!response.contains("unrelated-workload"));
                if project {
                    assert!(response.contains("GATEWAY_DOCKER_PROJECT_RESOURCE"));
                } else if status == 404 {
                    assert!(response.contains("GATEWAY_DOCKER_RESOURCE_NOT_FOUND"));
                }
                timeout(LIMIT, backend).await.unwrap().unwrap();
                proxy.shutdown().await;
            }
        }
    }
}

#[tokio::test]
async fn network_changes_require_management_of_the_referenced_container() {
    for operation in ["connect", "disconnect"] {
        for owned in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let container = "a".repeat(64);
            let network = "b".repeat(64);
            let image = format!("sha256:{}", "c".repeat(64));
            let mut definition = workloads(origin.local_addr().unwrap().port());
            let mut access = json!({"mode":"project","name":"alpha","adoption":"selection-1","shared":{"images":[image],"networks":[network]}});
            access[if owned { "selected" } else { "shared" }]["containers"] = json!([container]);
            definition["capabilities"]["engine"]["docker_access"] = access;
            let proxy = start(root.path(), definition, false, false).await;
            let target = format!("/v1.45/networks/{network}/{operation}");
            let forwarded = target.clone();
            let backend = tokio::spawn(async move {
                for (path, body) in [
                    (
                        "/v1.45/containers/ordinary/json".to_owned(),
                        json!({"Id":container,"Image":image,"HostConfig":{"Privileged":false,"CgroupnsMode":"private","NetworkMode":network},"NetworkSettings":{"Networks":{}},"Mounts":[]}),
                    ),
                    (
                        format!("/v1.45/networks/{network}"),
                        json!({"Id":network,"Driver":"bridge","Options":{},"IPAM":{"Driver":"default"}}),
                    ),
                    (
                        format!("/v1.45/images/{image}/json"),
                        json!({"Id":image,"Os":"linux","Config":{}}),
                    ),
                ] {
                    let (mut stream, _) = origin.accept().await.unwrap();
                    let headers = String::from_utf8(head(&mut stream).await).unwrap();
                    assert!(
                        headers.starts_with(&format!("GET {path} HTTP/1.1")),
                        "{headers}"
                    );
                    let body = body.to_string();
                    stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
                }
                if owned {
                    let (mut stream, _) = origin.accept().await.unwrap();
                    let headers = String::from_utf8(head(&mut stream).await).unwrap();
                    assert!(
                        headers.starts_with(&format!("POST {forwarded} HTTP/1.1")),
                        "{headers}"
                    );
                    let mut body = vec![0; json!({"Container":container}).to_string().len()];
                    stream.read_exact(&mut body).await.unwrap();
                    assert_eq!(
                        serde_json::from_slice::<Value>(&body).unwrap(),
                        json!({"Container":container})
                    );
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                        )
                        .await
                        .unwrap();
                } else {
                    assert!(
                        timeout(Duration::from_millis(100), origin.accept())
                            .await
                            .is_err()
                    );
                }
            });
            let response = call(
                root.path(),
                "alice",
                &request(
                    "POST",
                    &target,
                    "X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\nContent-Type: application/json\r\nConnection: close\r\n",
                    &serde_json::to_vec(&json!({"Container":"ordinary"})).unwrap(),
                ),
            )
            .await;
            assert!(
                response.starts_with(if owned {
                    b"HTTP/1.1 200"
                } else {
                    b"HTTP/1.1 404"
                }),
                "{}",
                String::from_utf8_lossy(&response)
            );
            timeout(LIMIT, backend).await.unwrap().unwrap();
            proxy.shutdown().await;
        }
    }
}

#[tokio::test]
async fn project_resource_updates_inspect_existing_state_without_create_defaults() {
    // Docker CLI 26.1.5, API 1.45, captured at a local synthetic endpoint.
    // These are fresh client captures, not the historical protected request.
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/docker/update-defaults.json")).unwrap();
    let mut cases: Vec<_> = fixtures
        .as_array()
        .unwrap()
        .iter()
        .map(|fixture| (fixture["body"].clone(), "safe"))
        .collect();
    cases.extend([
        (json!({}), "safe"),
        (json!({"NanoCpus":500000000}), "safe"),
        (json!({"RestartPolicy":null,"MemorySwappiness":-1}), "safe"),
    ]);
    for state in [
        "privileged",
        "socket-mount",
        "foreign-container",
        "shared-container",
        "foreign-network",
        "unsafe-network",
        "missing-network",
    ] {
        cases.push((fixtures[0]["body"].clone(), state));
    }
    for (body, state) in cases {
        let root = tempfile::tempdir().unwrap();
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let container = "a".repeat(64);
        let network = "b".repeat(64);
        let image = format!("sha256:{}", "c".repeat(64));
        let observed_container = if state == "foreign-container" {
            "e".repeat(64)
        } else {
            container.clone()
        };
        let observed_network = if state == "foreign-network" {
            "d".repeat(64)
        } else {
            network.clone()
        };
        let mut definition = workloads(origin.local_addr().unwrap().port());
        let mut access = json!({"mode":"project","name":"alpha","adoption":"selection-1","selected":{"networks":[network]},"shared":{"images":[image]}});
        access[if state == "shared-container" {
            "shared"
        } else {
            "selected"
        }]["containers"] = json!([container]);
        definition["capabilities"]["engine"]["docker_access"] = access;
        let proxy = start(root.path(), definition, false, false).await;
        let payload = serde_json::to_vec(&body).unwrap();
        let forwarded_body = payload.clone();
        let allowed = state == "safe";
        let backend = tokio::spawn(async move {
            let mounts = if state == "socket-mount" {
                json!([{"Type":"bind","Source":"/var/run/docker.sock","RW":false}])
            } else {
                json!([])
            };
            let mut inspections = vec![(
                "/v1.45/containers/ordinary-name/json".to_owned(),
                200,
                json!({"Id":observed_container,"Image":image,"HostConfig":{"Privileged":state == "privileged","CgroupnsMode":"private","NetworkMode":"ordinary-net"},"NetworkSettings":{"Networks":{"ordinary-net":{"NetworkID":observed_network}}},"Mounts":mounts}),
            )];
            if !["privileged", "socket-mount"].contains(&state) {
                let network_facts = json!({"Id":observed_network,"Name":"ordinary-net","Driver":if state == "unsafe-network" {"host"} else {"bridge"},"Options":{},"IPAM":{"Driver":"default"}});
                inspections.push((
                    format!("/v1.45/networks/{observed_network}"),
                    if state == "missing-network" { 404 } else { 200 },
                    network_facts.clone(),
                ));
                if !["unsafe-network", "missing-network"].contains(&state) {
                    inspections.push(("/v1.45/networks/ordinary-net".into(), 200, network_facts));
                    inspections.push((
                        format!("/v1.45/images/{image}/json"),
                        200,
                        json!({"Id":image,"Os":"linux","Config":{}}),
                    ));
                }
            }
            for (path, status, facts) in inspections {
                let (mut stream, _) = origin.accept().await.unwrap();
                let headers = String::from_utf8(head(&mut stream).await).unwrap();
                assert!(
                    headers.starts_with(&format!("GET {path} HTTP/1.1")),
                    "{state}: {headers}"
                );
                let facts = facts.to_string();
                stream.write_all(format!("HTTP/1.1 {status} Origin status\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{facts}",facts.len()).as_bytes()).await.unwrap();
            }
            if allowed {
                let (mut stream, _) = origin.accept().await.unwrap();
                let headers = String::from_utf8(head(&mut stream).await).unwrap();
                assert!(
                    headers.starts_with(&format!(
                        "POST /v1.45/containers/{container}/update HTTP/1.1"
                    )),
                    "{headers}"
                );
                let mut received = vec![0; forwarded_body.len()];
                stream.read_exact(&mut received).await.unwrap();
                assert_eq!(received, forwarded_body);
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"Warnings\":[]}").await.unwrap();
            } else {
                assert!(
                    timeout(Duration::from_millis(100), origin.accept())
                        .await
                        .is_err(),
                    "{state}: mutation after refusal"
                );
            }
        });
        let response = call(
            root.path(),
            "alice",
            &request(
                "POST",
                "/v1.45/containers/ordinary-name/update",
                "X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\nContent-Type: application/json\r\nConnection: close\r\n",
                &payload,
            ),
        )
        .await;
        assert!(
            response.starts_with(if allowed {
                b"HTTP/1.1 200"
            } else {
                b"HTTP/1.1 404"
            }),
            "{state}: {}",
            String::from_utf8_lossy(&response)
        );
        timeout(LIMIT, backend).await.unwrap().unwrap();
        proxy.shutdown().await;
    }
}

#[tokio::test]
async fn container_removal_preserves_shared_volumes_for_engine_boolean_encodings() {
    // API 1.45 uses httputils.BoolValue: trim/lowercase, then empty/0/no/false/none
    // are false. Every other value enables anonymous-volume deletion.
    // https://github.com/moby/moby/blob/v26.1.5/api/server/httputils/form.go
    for owned in [false, true] {
        for (query, removes_volumes) in [
            ("", false),
            ("?v", false),
            ("?v=", false),
            ("?v=0", false),
            ("?v=no", false),
            ("?v=false", false),
            ("?v=none", false),
            ("?v=+FaLsE+", false),
            ("?v=%09No%20", false),
            ("?v=%E2%80%83NoNe%C2%A0", false),
            ("?v=true", true),
            ("?v=truE", true),
            ("?v=+TrUe%09", true),
            ("?v=1", true),
            ("?v=yes", true),
            ("?v=off", true),
            ("?v=2", true),
        ] {
            let root = tempfile::tempdir().unwrap();
            let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let container = "a".repeat(64);
            let network = "b".repeat(64);
            let image = format!("sha256:{}", "c".repeat(64));
            let volume = "d".repeat(64);
            let created = "2026-11-07T00:00:00Z";
            let mut definition = workloads(origin.local_addr().unwrap().port());
            let mut access = json!({"mode":"project","name":"alpha","adoption":"selection-1","selected":{"containers":[container]},"shared":{"images":[image],"networks":[network]}});
            access[if owned { "selected" } else { "shared" }]["volumes"] =
                json!({volume.clone():created});
            definition["capabilities"]["engine"]["docker_access"] = access;
            let proxy = start(root.path(), definition, false, false).await;
            let allowed = owned || !removes_volumes;
            let backend = tokio::spawn(async move {
                let mut prerequisites = BTreeMap::from([
                    (
                        "/v1.45/containers/ordinary-name/json".to_owned(),
                        json!({"Id":container,"Image":image,"State":{"Status":"exited","Running":false},"HostConfig":{"Privileged":false,"CgroupnsMode":"private","NetworkMode":network},"NetworkSettings":{"Networks":{}},"Mounts":[{"Type":"volume","Name":volume,"Driver":"local","Destination":"/data","RW":true}]}),
                    ),
                    (
                        format!("/v1.45/networks/{network}"),
                        json!({"Id":network,"Driver":"bridge","Options":{},"IPAM":{"Driver":"default"}}),
                    ),
                    (
                        format!("/v1.45/images/{image}/json"),
                        json!({"Id":image,"Os":"linux","Config":{}}),
                    ),
                    (
                        format!("/v1.45/volumes/{volume}"),
                        json!({"Name":volume,"Driver":"local","Options":{},"CreatedAt":created}),
                    ),
                ]);
                let mut saw_events = false;
                for _ in 0..5 {
                    let (mut stream, _) = origin.accept().await.unwrap();
                    let headers = String::from_utf8(head(&mut stream).await).unwrap();
                    assert!(headers.starts_with("GET "), "{headers}");
                    let target = headers.split_whitespace().nth(1).unwrap();
                    let body = if target.starts_with("/v1.45/events?since=0&until=") {
                        assert!(!saw_events);
                        saw_events = true;
                        String::new()
                    } else {
                        prerequisites.remove(target).expect(target).to_string()
                    };
                    stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
                }
                assert!(prerequisites.is_empty() && saw_events);
                if allowed {
                    let (mut stream, _) = origin.accept().await.unwrap();
                    let headers = String::from_utf8(head(&mut stream).await).unwrap();
                    assert!(
                        headers.starts_with(&format!(
                            "DELETE /v1.45/containers/{container}{query} HTTP/1.1"
                        )),
                        "{headers}"
                    );
                    stream
                        .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                        .await
                        .unwrap();
                    let (mut stream, _) = origin.accept().await.unwrap();
                    let headers = String::from_utf8(head(&mut stream).await).unwrap();
                    assert!(headers.starts_with("GET /v1.45/events?since=0&until="));
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .unwrap();
                }
                assert!(
                    timeout(Duration::from_millis(50), origin.accept())
                        .await
                        .is_err(),
                    "owned={owned} {query}: unexpected mutation"
                );
            });
            let response = call(root.path(), "alice", &request("DELETE", &format!("/v1.45/containers/ordinary-name{query}"), "X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\nConnection: close\r\n", b"")).await;
            assert!(
                response.starts_with(if allowed {
                    b"HTTP/1.1 204"
                } else {
                    b"HTTP/1.1 404"
                }),
                "owned={owned} {query}: {}",
                String::from_utf8_lossy(&response)
            );
            timeout(LIMIT, backend).await.unwrap().unwrap();
            proxy.shutdown().await;
        }
    }
}

#[tokio::test]
async fn docker_default_endpoint_inspects_bridge_before_forwarding_the_cli_payload() {
    for (network_status, driver) in [(200, "bridge"), (404, "bridge"), (200, "host")] {
        let root = tempfile::tempdir().unwrap();
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = start(
            root.path(),
            workloads(origin.local_addr().unwrap().port()),
            false,
            false,
        )
        .await;
        let payload = include_bytes!("fixtures/docker/create-defaults.json");
        let allowed = network_status == 200 && driver == "bridge";
        let backend = tokio::spawn(async move {
            let mut inspections = vec![
                (
                    "/v1.45/info",
                    200,
                    json!({"OSType":"linux","SecurityOptions":["name=cgroupns"],"DefaultRuntime":"runc","LoggingDriver":"json-file"}),
                ),
                (
                    "/v1.45/networks/bridge",
                    network_status,
                    json!({"Id":"b".repeat(64),"Name":"bridge","Driver":driver,"Options":{"com.docker.network.bridge.default_bridge":"true","com.docker.network.bridge.name":"docker0"},"IPAM":{"Driver":"default"}}),
                ),
            ];
            if allowed {
                inspections.push((
                    "/v1.45/images/busybox:1.36/json",
                    200,
                    json!({"Os":"linux"}),
                ));
            }
            for (path, status, body) in inspections {
                let (mut stream, _) = origin.accept().await.unwrap();
                let headers = String::from_utf8(head(&mut stream).await).unwrap();
                assert!(
                    headers.starts_with(&format!("GET {path} HTTP/1.1")),
                    "{headers}"
                );
                assert!(!headers.contains("sgw_"));
                let body = body.to_string();
                stream.write_all(format!("HTTP/1.1 {status} Origin status\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
            }
            if allowed {
                let (mut stream, _) = origin.accept().await.unwrap();
                let headers = String::from_utf8(head(&mut stream).await).unwrap();
                assert!(
                    headers.starts_with("POST /v1.45/containers/create HTTP/1.1"),
                    "{headers}"
                );
                let mut forwarded = vec![0; payload.len()];
                stream.read_exact(&mut forwarded).await.unwrap();
                assert_eq!(forwarded, payload);
                let body = json!({"Id":"a".repeat(64),"Warnings":[]}).to_string();
                stream.write_all(format!("HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
            } else {
                assert!(
                    timeout(Duration::from_millis(100), origin.accept())
                        .await
                        .is_err()
                );
            }
        });
        let response = call(root.path(), "alice", &request("POST", "/v1.45/containers/create",
            "X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\nContent-Type: application/json\r\nConnection: close\r\n", payload)).await;
        assert!(
            response.starts_with(if allowed {
                b"HTTP/1.1 201"
            } else {
                b"HTTP/1.1 403"
            }),
            "{}",
            String::from_utf8_lossy(&response)
        );
        timeout(LIMIT, backend).await.unwrap().unwrap();
        proxy.shutdown().await;
    }
}

#[tokio::test]
async fn docker_network_ids_cannot_override_an_inspected_safe_network_name() {
    let root = tempfile::tempdir().unwrap();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = start(
        root.path(),
        workloads(origin.local_addr().unwrap().port()),
        false,
        false,
    )
    .await;
    let backend = tokio::spawn(async move {
        for (path, body) in [
            (
                "/v1.45/info",
                json!({"OSType":"linux","SecurityOptions":["name=cgroupns"],"DefaultRuntime":"runc","LoggingDriver":"json-file"}),
            ),
            (
                "/v1.45/networks/ordinary-name",
                json!({"Driver":"bridge","Options":{},"IPAM":{"Driver":"default"}}),
            ),
            (
                "/v1.45/networks/unsafe-id",
                json!({"Driver":"host","Options":{}}),
            ),
        ] {
            let (mut stream, _) = origin.accept().await.unwrap();
            let headers = String::from_utf8(head(&mut stream).await).unwrap();
            assert!(
                headers.starts_with(&format!("GET {path} HTTP/1.1")),
                "{headers}"
            );
            let body = body.to_string();
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        }
        assert!(
            timeout(Duration::from_millis(100), origin.accept())
                .await
                .is_err()
        );
    });
    let body = json!({"Image":"busybox","NetworkingConfig":{"EndpointsConfig":{"ordinary-name":{"GwPriority":1,"NetworkID":"unsafe-id"}}}});
    let response=call(root.path(),"alice",&request("POST","/v1.45/containers/create","X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\nContent-Type: application/json\r\nConnection: close\r\n",&serde_json::to_vec(&body).unwrap())).await;
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    assert!(String::from_utf8_lossy(&response).contains("GATEWAY_DOCKER_RESOURCE_CONSTRAINT"));
    timeout(LIMIT, backend).await.unwrap().unwrap();
    proxy.shutdown().await;
}

fn origin_tls(root: &Path, valid_name: bool) -> tokio_rustls::TlsAcceptor {
    let rcgen::CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(vec![
        if valid_name {
            "127.0.0.1"
        } else {
            "wrong-endpoint.invalid"
        }
        .into(),
    ])
    .unwrap();
    std::fs::write(root.join("origin-ca.pem"), cert.pem()).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let interception = params.self_signed(&key).unwrap();
    std::fs::write(
        root.join("interception-ca.pem"),
        format!("{}{}", key.serialize_pem(), interception.pem()),
    )
    .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    )
    .unwrap();
    tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config))
}

#[tokio::test]
async fn external_tls_verifies_endpoint_and_injects_only_the_operator_credential() {
    for valid_name in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = origin.local_addr().unwrap().port();
        let acceptor = origin_tls(root.path(), valid_name);
        let backend = tokio::spawn(async move {
            let (stream, _) = origin.accept().await.unwrap();
            let tls = acceptor.accept(stream).await;
            if !valid_name {
                assert!(tls.is_err());
                return;
            }
            let mut tls = tls.unwrap();
            let headers = String::from_utf8(head(&mut tls).await).unwrap();
            assert!(headers.contains(&format!("Bearer {ORIGIN_CREDENTIAL}")));
            assert!(!headers.contains("sgw_"));
            assert!(
                !headers
                    .to_ascii_lowercase()
                    .contains("x-safeyolo-docker-service")
            );
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });
        let mut definition = service(port);
        definition["docker"]["endpoint"] = json!(format!("https://127.0.0.1:{port}"));
        definition["auth"] = json!({"type":"bearer"});
        let proxy = start(root.path(), definition, false, false).await;
        let bytes = request(
            "GET",
            "/v1.45/info",
            "X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\nConnection: close\r\n",
            b"",
        );
        assert!(!String::from_utf8_lossy(&bytes).contains(ORIGIN_CREDENTIAL));
        let response = call(root.path(), "alice", &bytes).await;
        assert!(
            response.starts_with(if valid_name {
                b"HTTP/1.1 200"
            } else {
                b"HTTP/1.1 502"
            }),
            "{}",
            String::from_utf8_lossy(&response)
        );
        timeout(LIMIT, backend).await.unwrap().unwrap();
        proxy.shutdown().await;
        assert!(
            !serde_json::to_string(&events(root.path()))
                .unwrap()
                .contains(ORIGIN_CREDENTIAL)
        );
    }
}

#[tokio::test]
async fn docker_tls_exec_preserves_half_close_and_reports_truncation() {
    for (send_output, clean_eof) in [(true, true), (true, false), (false, false)] {
        let root = tempfile::tempdir().unwrap();
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = origin.local_addr().unwrap().port();
        let acceptor = origin_tls(root.path(), true);
        let mut definition = service(port);
        definition["docker"]["endpoint"] = json!(format!("https://127.0.0.1:{port}"));
        let proxy = start(root.path(), definition, false, false).await;
        let backend = tokio::spawn(async move {
            let (stream, _) = origin.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            head(&mut stream).await;
            let mut body = [0; 2];
            stream.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"{}");
            stream
                .write_all(b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
                .await
                .unwrap();
            let mut stdin = Vec::new();
            stream.read_to_end(&mut stdin).await.unwrap();
            assert!(stdin.is_empty());
            if send_output {
                stream.write_all(b"stdout-after-stdin-eof").await.unwrap();
            }
            if clean_eof {
                stream.shutdown().await.unwrap();
            }
        });
        let mut client = UnixStream::connect(root.path().join("alice.sock"))
            .await
            .unwrap();
        client.write_all(&request("POST", "/v1.45/exec/owned/start", "X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\nContent-Type: application/json\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n", b"{}")).await.unwrap();
        assert!(head(&mut client).await.starts_with(b"HTTP/1.1 101"));
        client.shutdown().await.unwrap();
        let mut output = Vec::new();
        timeout(LIMIT, client.read_to_end(&mut output))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            output,
            if send_output {
                b"stdout-after-stdin-eof".as_slice()
            } else {
                b""
            }
        );
        timeout(LIMIT, backend).await.unwrap().unwrap();
        proxy.shutdown().await;
        let rows = events(root.path());
        let end = rows
            .iter()
            .find(|row| row["event"] == "gateway.docker_stream.end")
            .unwrap();
        assert_eq!(
            end["details"]["stream_outcome"],
            if clean_eof { "completed" } else { "error" }
        );
        assert_eq!(end["details"]["uploaded_bytes"], 0);
        assert_eq!(end["details"]["downloaded_bytes"], output.len());
        if clean_eof {
            assert!(end["details"]["error"].is_null());
        } else {
            assert_eq!(
                end["details"]["error"],
                json!({"direction":"download", "operation":"read", "kind":"UnexpectedEof", "os_error":null})
            );
        }
    }
}

#[tokio::test]
async fn docker_exec_and_attach_preserve_buffered_bytes_and_half_close() {
    for path in [
        "/v1.45/exec/owned/start",
        "/v1.45/containers/owned/attach?stream=1&stdin=1&stdout=1",
    ] {
        let root = tempfile::tempdir().unwrap();
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = origin.local_addr().unwrap().port();
        let proxy = start(root.path(), service(port), false, false).await;
        let backend = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let headers = String::from_utf8(head(&mut stream).await).unwrap();
            assert!(!headers.contains("sgw_"));
            assert!(
                !headers
                    .to_ascii_lowercase()
                    .contains("x-safeyolo-docker-service")
            );
            assert!(
                headers
                    .to_ascii_lowercase()
                    .contains(&format!("host: 127.0.0.1:{port}"))
            );
            let mut body = [0; 2];
            stream.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"{}");
            stream.write_all(b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Type: application/vnd.docker.raw-stream\r\n\r\nready").await.unwrap();
            let mut stdin = Vec::new();
            stream.read_to_end(&mut stdin).await.unwrap();
            assert_eq!(stdin, b"process stdin");
            stream.write_all(b"after-eof").await.unwrap();
            stream.shutdown().await.unwrap();
            headers
        });
        let mut client = UnixStream::connect(root.path().join("alice.sock"))
            .await
            .unwrap();
        client.write_all(&request("POST",path,"X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\nContent-Type: application/json\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n",b"{}")).await.unwrap();
        let response = head(&mut client).await;
        assert!(
            response.starts_with(b"HTTP/1.1 101"),
            "{}",
            String::from_utf8_lossy(&response)
        );
        let mut ready = [0; 5];
        timeout(LIMIT, client.read_exact(&mut ready))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&ready, b"ready");
        client.write_all(b"process stdin").await.unwrap();
        client.shutdown().await.unwrap();
        let mut tail = Vec::new();
        timeout(LIMIT, client.read_to_end(&mut tail))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tail, b"after-eof");
        let seen = timeout(LIMIT, backend).await.unwrap().unwrap();
        assert!(seen.starts_with(&format!("POST {path} HTTP/1.1")));
        proxy.shutdown().await;
        let rows = events(root.path());
        let end = rows
            .iter()
            .find(|row| row["event"] == "gateway.docker_stream.end")
            .unwrap();
        assert_eq!(end["details"]["stream_outcome"], "completed");
        assert_eq!(end["details"]["uploaded_bytes"], 13);
        assert_eq!(end["details"]["downloaded_bytes"], 14);
        assert_eq!(end["details"]["operation_outcome"], "unknown");
    }
}

#[tokio::test]
async fn configured_docker_endpoint_cannot_be_reached_without_its_capability() {
    let root = tempfile::tempdir().unwrap();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = origin.local_addr().unwrap().port();
    let proxy = start(root.path(), service(port), true, false).await;
    for (agent, method, path, extra) in [
        (
            "alice",
            "GET",
            format!("http://127.0.0.1:{port}/v1.45/info"),
            "",
        ),
        (
            "alice",
            "GET",
            "/v1.45/info".into(),
            "X-SafeYolo-Docker-Service: docker-test\r\n",
        ),
        (
            "alice",
            "GET",
            "/v1.45/info".into(),
            "X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_bad\r\n",
        ),
        (
            "bob",
            "GET",
            "/v1.45/info".into(),
            "X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\n",
        ),
        ("alice", "CONNECT", format!("127.0.0.1:{port}"), ""),
        (
            "alice",
            "POST",
            "/v1.45/session".into(),
            "X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n",
        ),
        (
            "alice",
            "POST",
            "/v1.45/containers/create".into(),
            "X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\n",
        ),
        (
            "alice",
            "POST",
            "/containers/create".into(),
            "X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\n",
        ),
        (
            "alice",
            "GET",
            "/v1.44/info".into(),
            "X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\n",
        ),
        (
            "alice",
            "GET",
            "/v1.450/info".into(),
            "X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\n",
        ),
        (
            "alice",
            "POST",
            "/v1.45/containers//owned/start".into(),
            "X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\n",
        ),
        (
            "alice",
            "POST",
            "/v1.45/containers/create".into(),
            "X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n",
        ),
    ] {
        let response = call(
            root.path(),
            agent,
            &request(method, &path, &format!("{extra}Connection: close\r\n"), b""),
        )
        .await;
        assert!(
            response.starts_with(b"HTTP/1.1 403"),
            "{method} {path}: {}",
            String::from_utf8_lossy(&response)
        );
        assert!(
            timeout(Duration::from_millis(20), origin.accept())
                .await
                .is_err(),
            "refused request reached upstream"
        );
    }
    // The same hostname at another port keeps ordinary network policy.
    let other = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let other_port = other.local_addr().unwrap().port();
    let backend = tokio::spawn(async move {
        let (mut stream, _) = other.accept().await.unwrap();
        head(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
    });
    let response = call(
        root.path(),
        "alice",
        &request(
            "GET",
            &format!("http://127.0.0.1:{other_port}/ordinary"),
            "Connection: close\r\n",
            b"",
        ),
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    timeout(LIMIT, backend).await.unwrap().unwrap();
    proxy.shutdown().await;
}

#[tokio::test]
async fn existing_resource_names_do_not_become_reserved_words() {
    let root = tempfile::tempdir().unwrap();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = origin.local_addr().unwrap().port();
    let proxy = start(root.path(), service(port), false, false).await;
    let backend = tokio::spawn(async move {
        for _ in 0..3 {
            let (mut stream, _) = origin.accept().await.unwrap();
            head(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        }
    });
    for (method, path) in [
        ("DELETE", "/v1.45/containers/json"),
        ("GET", "/v1.45/networks/create"),
        ("DELETE", "/v1.45/images/example/json"),
    ] {
        let response = call(root.path(), "alice", &request(method,path,"X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\nConnection: close\r\n",b"")).await;
        assert!(
            response.starts_with(b"HTTP/1.1 200"),
            "{}",
            String::from_utf8_lossy(&response)
        );
    }
    timeout(LIMIT, backend).await.unwrap().unwrap();
    proxy.shutdown().await;
}

#[tokio::test]
async fn body_value_constraints_require_json_inspection_before_mutation() {
    let root = tempfile::tempdir().unwrap();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut definition = service(origin.local_addr().unwrap().port());
    definition["capabilities"]["engine"]["contract"] = json!({"template":"image.v1","operations":[{"name":"create","request":{
        "method":"POST","path":"/v1.45/containers/create",
        "body":{"deny_unknown":false,"values":{"type":"string","enum":["busybox"]}},
        "transport":{"body_format":"opaque","content_types":["application/json"]}
    }}],"enforcement":{"request_shape":"enforced","transport_hygiene":"enforced"}});
    assert!(safeyolo_proxy::services::ServiceDefinition::from_value(definition.clone()).is_err());
    definition["capabilities"]["engine"]["contract"]["operations"][0]["request"]["transport"]["body_format"] =
        json!("json_object");
    let proxy = start(root.path(), definition, false, false).await;
    let backend = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let headers = String::from_utf8(head(&mut stream).await).unwrap();
        assert!(headers.starts_with("POST /v1.45/containers/create HTTP/1.1"));
        let expected = br#"{"Image":"busybox"}"#;
        let mut body = vec![0; expected.len()];
        stream.read_exact(&mut body).await.unwrap();
        assert_eq!(body, expected);
        stream
            .write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
            .await
            .unwrap();
        origin
    });
    let response = call(root.path(), "alice", &request("POST", "/v1.45/containers/create", "X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\nContent-Type: application/json\r\nConnection: close\r\n", br#"{"Image":"busybox"}"#)).await;
    assert!(
        response.starts_with(b"HTTP/1.1 201"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    let origin = timeout(LIMIT, backend).await.unwrap().unwrap();
    for body in [
        br#"{"Image":"unapproved-image"}"#.as_slice(),
        br#"{"Image":"busybox","Another":"unapproved-image"}"#.as_slice(),
    ] {
        let response = call(root.path(), "alice", &request("POST", "/v1.45/containers/create", "X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\nContent-Type: application/json\r\nConnection: close\r\n", body)).await;
        assert!(
            response.starts_with(b"HTTP/1.1 403"),
            "{}",
            String::from_utf8_lossy(&response)
        );
        assert!(
            timeout(Duration::from_millis(50), origin.accept())
                .await
                .is_err()
        );
    }
    proxy.shutdown().await;
}

#[tokio::test]
async fn streaming_archive_keeps_contract_validation_before_upstream_mutation() {
    let root = tempfile::tempdir().unwrap();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = origin.local_addr().unwrap().port();
    let mut definition = service(port);
    definition["capabilities"]["engine"]["contract"] = json!({"template":"build.v1","operations":[{"name":"build","request":{
        "method":"POST","path":"/v1.45/build","transport":{"body_format":"opaque","content_types":["application/x-tar"]},
        "query":{"allow":{"version":{"integer_range":[1,1]}},"deny_unknown":true}
    }}],"enforcement":{"request_shape":"enforced","transport_hygiene":"enforced"}});
    let proxy = start(root.path(), definition, false, false).await;
    for (path, content_type) in [
        ("/v1.45/build?version=2", "application/x-tar"),
        ("/v1.45/build?version=1", "application/json"),
    ] {
        let response=call(root.path(),"alice",&request("POST",path,&format!("X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\nContent-Type: {content_type}\r\nConnection: close\r\n"),b"not-json")).await;
        assert!(
            response.starts_with(b"HTTP/1.1 403"),
            "{}",
            String::from_utf8_lossy(&response)
        );
        assert!(
            timeout(Duration::from_millis(20), origin.accept())
                .await
                .is_err()
        );
    }
    let size = BUFFERED_BODY_THRESHOLD + 1024;
    let backend = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let headers = String::from_utf8(head(&mut stream).await).unwrap();
        assert!(!headers.contains("sgw_"));
        let mut payload = vec![0; size];
        stream.read_exact(&mut payload).await.unwrap();
        assert!(payload.iter().all(|byte| *byte == 0xa5));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });
    let payload = vec![0xa5; size];
    let response=call(root.path(),"alice",&request("POST","/v1.45/build?version=1","X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\nContent-Type: application/x-tar\r\nConnection: close\r\n",&payload)).await;
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    timeout(LIMIT, backend).await.unwrap().unwrap();
    proxy.shutdown().await;
}

#[tokio::test]
async fn unavailable_required_body_inspection_refuses_before_mutation() {
    for scan in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = origin.local_addr().unwrap().port();
        let mut definition = service(port);
        if !scan {
            definition["capabilities"]["engine"]["contract"] = json!({"template":"json.v1","operations":[{"name":"build","request":{"method":"POST","path":"/v1.45/build"}}],"enforcement":{"request_shape":"enforced"}});
        }
        let proxy = start(root.path(), definition, false, scan).await;
        // A known body above the capture limit must be refused without waiting
        // for an upload or opening an upstream connection.
        let bytes = format!(
            "POST /v1.45/build HTTP/1.1\r\nHost: proxy.invalid:3128\r\nX-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            BUFFERED_BODY_THRESHOLD + 1
        );
        let reply = call(root.path(), "alice", bytes.as_bytes()).await;
        assert!(
            reply.starts_with(if scan {
                b"HTTP/1.1 403"
            } else {
                b"HTTP/1.1 503"
            }),
            "{}",
            String::from_utf8_lossy(&reply)
        );
        assert!(String::from_utf8_lossy(&reply).contains(if scan {
            "body_unavailable"
        } else {
            "GATEWAY_BODY_UNAVAILABLE"
        }));
        assert!(
            timeout(Duration::from_millis(20), origin.accept())
                .await
                .is_err()
        );
        proxy.shutdown().await;
    }
}

#[tokio::test]
async fn interrupted_mutation_response_is_canonical_and_never_replayed() {
    let root = tempfile::tempdir().unwrap();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = origin.local_addr().unwrap().port();
    let proxy = start(root.path(), service(port), false, false).await;
    let backend = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        head(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\npartial")
            .await
            .unwrap();
        drop(stream);
        assert!(
            timeout(Duration::from_millis(200), origin.accept())
                .await
                .is_err(),
            "mutation replayed"
        );
    });
    let _response=call(root.path(),"alice",&request("POST","/v1.45/containers/owned/start","X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\nConnection: close\r\n",b"")).await;
    timeout(LIMIT, backend).await.unwrap().unwrap();
    proxy.shutdown().await;
    let rows = events(root.path());
    let row = rows
        .iter()
        .find(|row| row["event"] == "gateway.docker_request")
        .unwrap();
    assert_eq!(row["details"]["mutation_outcome"], "unknown");
    assert_eq!(row["details"]["replayed"], false);
}

#[tokio::test]
async fn project_reconciles_an_interrupted_creation_before_returning_the_resource() {
    let root = tempfile::tempdir().unwrap();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut definition = workloads(origin.local_addr().unwrap().port());
    definition["capabilities"]["engine"]["docker_access"] = json!({"mode":"project","name":"alpha","adoption":"operator-selection-1","shared":{"images":[format!("sha256:{}","c".repeat(64))],"networks":["d".repeat(64)]}});
    let proxy = start(root.path(), definition, false, false).await;
    let backend = tokio::spawn(async move {
        let mut marker = String::new();
        let mut created = 0;
        loop {
            let (mut stream, _) = origin.accept().await.unwrap();
            let headers = String::from_utf8(head(&mut stream).await).unwrap();
            let target = headers
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap();
            let length: usize = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':')
                        .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                        .map(|(_, v)| v.trim().parse().unwrap())
                })
                .unwrap_or(0);
            let mut body = vec![0; length];
            stream.read_exact(&mut body).await.unwrap();
            let mut finished = false;
            let response = if headers.starts_with("POST ") {
                assert_eq!(target, "/v1.45/containers/create?name=ordinary-new");
                created += 1;
                assert_eq!(created, 1, "uncertain mutation was replayed");
                let value: Value = serde_json::from_slice(&body).unwrap();
                marker = value["Labels"]["io.safeyolo.creation"]
                    .as_str()
                    .unwrap()
                    .into();
                assert_ne!(marker, "client-forgery");
                assert_eq!(value["Image"], format!("sha256:{}", "c".repeat(64)));
                // The origin accepted the mutation and produced an ID, then
                // closed before the declared response body was complete.
                stream.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n{\"Id\":\"").await.unwrap();
                drop(stream);
                continue;
            } else if target == "/v1.45/info" {
                json!({"OSType":"linux","DefaultRuntime":"runc","LoggingDriver":"json-file","SecurityOptions":["name=cgroupns"]})
            } else if target.starts_with("/v1.45/images/") {
                json!({"Id":format!("sha256:{}","c".repeat(64)),"Os":"linux","Config":{"Volumes":{}}})
            } else if target == "/v1.45/networks/bridge" {
                json!({"Id":"d".repeat(64),"Name":"bridge","Driver":"bridge","Options":{},"IPAM":{"Driver":"default"}})
            } else if target.starts_with("/v1.45/containers/") {
                if marker.is_empty() {
                    stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
                    continue;
                }
                finished = target == format!("/v1.45/containers/{}/json", "e".repeat(64));
                json!({"Id":"e".repeat(64),"Name":"/ordinary-new","Image":format!("sha256:{}","c".repeat(64)),"Config":{"Labels":{"io.safeyolo.creation":marker}},"HostConfig":{"Privileged":false,"CgroupnsMode":"private","NetworkMode":"bridge"},"NetworkSettings":{"Networks":{}},"Mounts":[]})
            } else {
                panic!("unexpected prerequisite {target}");
            };
            let body = serde_json::to_vec(&response).unwrap();
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
            drop(stream);
            if finished {
                return created;
            }
        }
    });
    let headers = "X-SafeYolo-Docker-Service: docker-test\r\nAuthorization: Bearer sgw_alice\r\nContent-Type: application/json\r\nConnection: close\r\n";
    let response=call(root.path(),"alice",&request("POST","/v1.45/containers/create?name=ordinary-new",headers,&serde_json::to_vec(&json!({"Image":"busybox","Labels":{"io.safeyolo.creation":"client-forgery"},"HostConfig":{"CgroupnsMode":"private"}})).unwrap())).await;
    assert!(
        response.starts_with(b"HTTP/1.1 503"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    let response = call(
        root.path(),
        "alice",
        &request("GET", "/v1.45/containers/ordinary-new/json", headers, b""),
    )
    .await;
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    let response = String::from_utf8(response).unwrap();
    assert!(response.contains("ordinary-new") && !response.contains("io.safeyolo.creation"));
    assert_eq!(timeout(LIMIT, backend).await.unwrap().unwrap(), 1);
    assert!(
        events(root.path())
            .iter()
            .any(|event| event["event"] == "gateway.docker_reconciled")
    );
    proxy.shutdown().await;
}
