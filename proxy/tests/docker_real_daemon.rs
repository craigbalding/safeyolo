//! Finite real Engine/Compose witness for #1437 and #1438. The operator supplies
//! an owned disposable daemon, authenticated HTTPS endpoint and private inputs.
//! This test does not provision a daemon or establish nested sandbox isolation.

use safeyolo_proxy::{
    Config, Proxy,
    credentials::{Credential, Secret},
};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    process::Command,
    time::timeout,
};

const AGENT_API_TOKEN: &str = "synthetic-docker-witness-agent-api";
const LIMIT: Duration = Duration::from_secs(180);

struct Inputs {
    endpoint: String,
    ca: PathBuf,
    credential: String,
    image: String,
}
impl Inputs {
    fn read() -> Self {
        let endpoint = std::env::var("SAFEYOLO_DOCKER_ENDPOINT")
            .expect("owned HTTPS Docker endpoint required");
        assert!(
            endpoint.starts_with("https://"),
            "real proof requires authenticated HTTPS"
        );
        let ca = PathBuf::from(
            std::env::var_os("SAFEYOLO_DOCKER_CA_FILE").expect("endpoint CA file required"),
        );
        let credential = std::fs::read_to_string(
            std::env::var_os("SAFEYOLO_DOCKER_CREDENTIAL_FILE")
                .expect("private bearer file required"),
        )
        .unwrap()
        .trim()
        .to_owned();
        assert!(!credential.is_empty() && !credential.contains(['\r', '\n']));
        Self {
            endpoint,
            ca,
            credential,
            image: std::env::var("SAFEYOLO_DOCKER_IMAGE").unwrap_or_else(|_| "busybox:1.36".into()),
        }
    }
}

async fn start(root: &Path, inputs: &Inputs, expired: bool) -> Proxy {
    start_with_access(root, inputs, expired, None).await
}
async fn start_with_access(
    root: &Path,
    inputs: &Inputs,
    expired: bool,
    access: Option<Value>,
) -> Proxy {
    std::fs::create_dir_all(root.join("builtin")).unwrap();
    std::fs::create_dir_all(root.join("services")).unwrap();
    std::fs::create_dir_all(root.join("client")).unwrap();
    let mut definition = safeyolo_proxy::services::ServiceDefinition::from_yaml(include_str!(
        "../../contrib/docker/service.yaml"
    ))
    .unwrap()
    .raw;
    if let Some(access) = access {
        definition["capabilities"]["workloads"]["docker_access"] = access;
    }
    definition["name"] = json!("docker-proof");
    definition["docker"]["endpoint"] = json!(inputs.endpoint);
    let endpoint: hyper::Uri = inputs.endpoint.parse().unwrap();
    definition["default_host"] = json!(endpoint.host().unwrap());
    std::fs::write(root.join("services/docker.yaml"), definition.to_string()).unwrap();
    // TOML service authorizations mint the scoped token and let runtime open
    // the native grant store used by the adopted effect-model admission.
    let policy = json!({
        "hosts": {
            endpoint.host().unwrap(): {"service":"docker-proof", "credentials":["unknown:*"]},
            format!("{}:{}", endpoint.host().unwrap(), endpoint.port_u16().unwrap_or(443)): {"egress":"allow"}
        },
        "agents": {"witness": {"services": {"docker-proof": {
            "capability":"workloads", "token":"docker-origin", "account":"proof"
        }}}}
    });
    std::fs::write(root.join("policy.toml"), toml::to_string(&policy).unwrap()).unwrap();
    let vault = safeyolo_proxy::credentials::open(&root.join("data")).unwrap();
    let mut credential = Credential::new(
        "docker-origin",
        "bearer",
        Secret::new(inputs.credential.clone()),
    );
    if expired {
        credential.expires_at = Some("2000-01-01T00:00:00Z".into());
    }
    vault.store(credential).unwrap();
    std::fs::write(root.join("data/agent_token"), AGENT_API_TOKEN).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let ca = params.self_signed(&key).unwrap();
    std::fs::write(
        root.join("interception.pem"),
        format!("{}{}", key.serialize_pem(), ca.pem()),
    )
    .unwrap();
    let config:Config=serde_json::from_value(json!({"listeners":[{"agent_id":"witness","socket_path":root.join("docker.sock")}],"policy_file":root.join("policy.toml"),
        "gateway_builtin_services_dir":root.join("builtin"),"gateway_services_dir":root.join("services"),"data_dir":root.join("data"),"readiness_file":root.join("ready"),
        "audit_log_path":root.join("audit.jsonl"),"flow_store_enabled":false,"flow_store_db_path":root.join("flows.sqlite3"),"circuit_breaker_enabled":false,"circuit_state_file":"",
        "tls_ca_file":root.join("interception.pem"),"upstream_ca_file":inputs.ca})).unwrap();
    let proxy = Proxy::start(config).await.unwrap();
    let (status, response) = wire(root, format!("GET http://_safeyolo.proxy.internal/gateway/services HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {AGENT_API_TOKEN}\r\nConnection: close\r\n\r\n").as_bytes()).await;
    assert_eq!(status, 200, "witness service discovery failed");
    let view: Value = serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(view["agent"], "witness");
    let service = &view["authorized"]["docker-proof"];
    assert_eq!(service["capability"], "workloads");
    let token = service["token"].as_str().expect("native workload token");
    std::fs::write(root.join("client/config.json"),json!({"HttpHeaders":{"X-SafeYolo-Docker-Service":"docker-proof","Authorization":format!("Bearer {token}")}}).to_string()).unwrap();
    proxy
}

fn docker(root: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("docker");
    command
        .args(args)
        .kill_on_drop(true)
        .env(
            "DOCKER_HOST",
            format!("unix://{}", root.join("docker.sock").display()),
        )
        .env("DOCKER_CONFIG", root.join("client"))
        .env("DOCKER_API_VERSION", "1.45")
        .env("DOCKER_BUILDKIT", "0")
        .env("COMPOSE_DOCKER_CLI_BUILD", "0")
        .env_remove("DOCKER_CONTEXT")
        .env_remove("DOCKER_TLS_VERIFY")
        .env_remove("DOCKER_CERT_PATH");
    command
}
async fn run(root: &Path, args: &[&str]) -> String {
    String::from_utf8(run_output(root, args).await.stdout).unwrap()
}
async fn run_output(root: &Path, args: &[&str]) -> std::process::Output {
    let out = timeout(LIMIT, docker(root, args).output())
        .await
        .expect("Docker client deadline")
        .unwrap();
    assert!(
        out.status.success(),
        "docker {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}
async fn api(root: &Path, method: &str, path: &str, body: &Value) -> (u16, String) {
    let body = if body.is_null() {
        Vec::new()
    } else {
        serde_json::to_vec(body).unwrap()
    };
    let client: Value =
        serde_json::from_slice(&std::fs::read(root.join("client/config.json")).unwrap()).unwrap();
    let authorization = client["HttpHeaders"]["Authorization"].as_str().unwrap();
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: gateway.invalid\r\nX-SafeYolo-Docker-Service: docker-proof\r\nAuthorization: {authorization}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).into_bytes();
    request.extend_from_slice(&body);
    wire(root, &request).await
}

async fn wire(root: &Path, request: &[u8]) -> (u16, String) {
    let mut stream = UnixStream::connect(root.join("docker.sock")).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut response = Vec::new();
    timeout(LIMIT, stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8_lossy(&response).into_owned();
    let status = response.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, response)
}

/// Fixture-only operator path. The bearer travels on stdin, and curl verifies
/// the configured CA/name. It never follows redirects or repeats a mutation.
async fn operator(
    inputs: &Inputs,
    root: &Path,
    method: &str,
    path: &str,
    body: &Value,
) -> (u16, Value) {
    let payload = root.join("operator-body.json");
    std::fs::write(&payload, serde_json::to_vec(body).unwrap()).unwrap();
    let mut command = Command::new("curl");
    command
        .kill_on_drop(true)
        .args(["--silent", "--show-error", "--cacert"])
        .arg(&inputs.ca)
        .args([
            "--header",
            "@-",
            "--request",
            method,
            "--write-out",
            "\n%{http_code}",
            "--header",
            "Content-Type: application/json",
        ]);
    if !body.is_null() {
        command
            .arg("--data-binary")
            .arg(format!("@{}", payload.display()));
    }
    command
        .arg(format!("{}{path}", inputs.endpoint.trim_end_matches('/')))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("Authorization: Bearer {}\n", inputs.credential).as_bytes())
        .await
        .unwrap();
    let output = timeout(LIMIT, child.wait_with_output())
        .await
        .expect("operator observation deadline")
        .unwrap();
    assert!(
        output.status.success(),
        "operator endpoint failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    let (body, status) = text.rsplit_once('\n').unwrap();
    (
        status.parse().unwrap(),
        serde_json::from_str(body).unwrap_or(Value::Null),
    )
}

#[tokio::test]
#[ignore = "requires operator-owned disposable Engine, HTTPS CA/bearer files, Docker and Compose; see contrib/docker/proof.md"]
async fn real_docker_compose_enforcement_and_persistent_effects() {
    let inputs = Inputs::read();
    let parent = PathBuf::from(
        std::env::var_os("SAFEYOLO_DOCKER_PROOF_ROOT")
            .expect("disk-backed owned scratch parent required"),
    );
    let root = tempfile::Builder::new()
        .prefix("docker-proof-")
        .tempdir_in(parent)
        .unwrap()
        .keep();
    let client = root.as_path().join("client-instance");
    let prefix = format!(
        "syproof{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    println!(
        "Docker/Compose real-boundary proof: owned resource prefix {prefix}; private scratch {}",
        root.display()
    );
    let mut proxy = start(&client, &inputs, false).await;
    println!("{}", run(&client, &["version"]).await);
    println!("{}", run(&client, &["compose", "version"]).await);
    run(&client, &["pull", &inputs.image]).await;
    let build = root.as_path().join("context");
    std::fs::create_dir(&build).unwrap();
    std::fs::write(
        build.join("Dockerfile"),
        format!("FROM {}\nCOPY seed /seed\n", inputs.image),
    )
    .unwrap();
    std::fs::write(build.join("seed"), "built-through-gateway\n").unwrap();
    let image = format!("{prefix}:proof");
    run(&client, &["build", "-t", &image, build.to_str().unwrap()]).await;
    let compose = root.as_path().join("compose.yaml");
    std::fs::write(&compose,format!("services:\n  web:\n    image: {image}\n    command: [sh, -c, 'mkdir -p /www; cp /seed /www/index.html; httpd -f -p 8080 -h /www']\n    healthcheck:\n      test: [CMD, wget, -qO-, 'http://127.0.0.1:8080']\n      interval: 1s\n      retries: 30\n  worker:\n    image: {image}\n    command: [sh, -c, 'echo worker-ready; sleep 3600']\n    volumes: [data:/data]\nvolumes:\n  data: {{}}\n")).unwrap();
    let cf = compose.to_str().unwrap();
    run(
        &client,
        &[
            "compose",
            "-p",
            &prefix,
            "-f",
            cf,
            "up",
            "-d",
            "--wait",
            "--wait-timeout",
            "45",
        ],
    )
    .await;
    let worker = run(
        &client,
        &["compose", "-p", &prefix, "-f", cf, "ps", "-q", "worker"],
    )
    .await
    .trim()
    .to_owned();
    let web = run(
        &client,
        &["compose", "-p", &prefix, "-f", cf, "ps", "-q", "web"],
    )
    .await
    .trim()
    .to_owned();
    let exec_output = run_output(
        &client,
        &[
            "exec",
            &worker,
            "sh",
            "-c",
            "wget -qO- http://web:8080; echo retained > /data/value",
        ],
    )
    .await;
    assert!(
        String::from_utf8_lossy(&exec_output.stdout).contains("built-through-gateway"),
        "exec stdout marker missing; stdout={:?}; stderr={:?}",
        String::from_utf8_lossy(&exec_output.stdout),
        String::from_utf8_lossy(&exec_output.stderr),
    );
    run(
        &client,
        &["compose", "-p", &prefix, "-f", cf, "logs", "--no-color"],
    )
    .await;
    run(&client, &["top", &worker]).await;
    let copied = root.as_path().join("copied");
    std::fs::write(&copied, "copy-round-trip").unwrap();
    run(
        &client,
        &["cp", copied.to_str().unwrap(), &format!("{worker}:/copied")],
    )
    .await;
    let returned = root.as_path().join("returned");
    run(
        &client,
        &[
            "cp",
            &format!("{worker}:/copied"),
            returned.to_str().unwrap(),
        ],
    )
    .await;
    assert_eq!(std::fs::read(returned).unwrap(), b"copy-round-trip");
    let mut child = docker(&client, &["exec", "-i", &worker, "cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"interactive-half-close\n")
        .await
        .unwrap();
    let output = timeout(LIMIT, child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(output.status.success(), "interactive exec failed");
    assert_eq!(output.stdout, b"interactive-half-close\n");
    let attached = format!("{prefix}-attach");
    run(
        &client,
        &[
            "create",
            "-i",
            "--name",
            &attached,
            &inputs.image,
            "sh",
            "-c",
            "read line; echo received:$line",
        ],
    )
    .await;
    run(&client, &["start", &attached]).await;
    let mut child = docker(&client, &["attach", "--sig-proxy=false", &attached])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"attach-half-close\n")
        .await
        .unwrap();
    let output = timeout(LIMIT, child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(output.status.success(), "interactive attach failed");
    assert!(String::from_utf8_lossy(&output.stdout).contains("received:attach-half-close"));
    assert!(
        run(&client, &["logs", "--follow", &attached])
            .await
            .contains("received:attach-half-close")
    );
    run(&client, &["rm", &attached]).await;
    run(
        &client,
        &[
            "compose",
            "-p",
            &prefix,
            "-f",
            cf,
            "up",
            "-d",
            "--force-recreate",
            "--wait",
            "--wait-timeout",
            "45",
        ],
    )
    .await;
    let worker = run(
        &client,
        &["compose", "-p", &prefix, "-f", cf, "ps", "-q", "worker"],
    )
    .await
    .trim()
    .to_owned();
    assert!(
        run(&client, &["exec", &worker, "cat", "/data/value"])
            .await
            .contains("retained")
    );

    for (index,host) in [json!({"Privileged":true}),json!({"NetworkMode":"host"}),json!({"PidMode":"host"}),json!({"IpcMode":"host"}),json!({"Devices":[{"PathOnHost":"/dev/null","PathInContainer":"/dev/null","CgroupPermissions":"rwm"}]}),json!({"CapAdd":["SYS_ADMIN"]}),json!({"SecurityOpt":["seccomp=unconfined"]}),json!({"Binds":["/var/run/docker.sock:/socket"]}),json!({"Mounts":[{"Type":"bind","Source":"/","Target":"/host"}]}),json!({"Mounts":[{"Type":"volume","Target":"/host","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"none","o":"bind","device":"/"}}}}]})].into_iter().enumerate() {
        let name=format!("{prefix}-forbidden-{index}");
        let (status,response)=api(&client,"POST",&format!("/v1.45/containers/create?name={name}"),&json!({"Image":inputs.image,"HostConfig":host})).await;
        assert_eq!(status,403,"{response}");assert!(response.contains("GATEWAY_DOCKER_CONSTRAINT"));
        assert_eq!(operator(&inputs,root.as_path(),"GET",&format!("/v1.45/containers/{name}/json"),&Value::Null).await.0,404,"forbidden container reached the daemon");
    }
    let unsafe_name = format!("{prefix}-unsafe-existing");
    let (status, unsafe_container) = operator(
        &inputs,
        root.as_path(),
        "POST",
        &format!("/v1.45/containers/create?name={unsafe_name}"),
        &json!({"Image":inputs.image,"Cmd":["sleep","3600"],"HostConfig":{"Privileged":true}}),
    )
    .await;
    assert_eq!(status, 201);
    for path in [
        format!("/v1.45/containers/{unsafe_name}/start"),
        format!("/v1.45/containers/{unsafe_name}/exec"),
    ] {
        let (status, response) = api(
            &client,
            "POST",
            &path,
            &if path.ends_with("exec") {
                json!({"Cmd":["id"]})
            } else {
                Value::Null
            },
        )
        .await;
        assert_eq!(status, 403, "{response}");
        assert!(response.contains("GATEWAY_DOCKER_RESOURCE_CONSTRAINT"));
    }
    let (_, state) = operator(
        &inputs,
        root.as_path(),
        "GET",
        &format!("/v1.45/containers/{unsafe_name}/json"),
        &Value::Null,
    )
    .await;
    assert_eq!(
        state["State"]["Running"], false,
        "unsafe existing workload was started"
    );
    let unsafe_id = unsafe_container["Id"].as_str().unwrap();
    for host in [
        json!({"VolumesFrom":[format!("{unsafe_name}:ro")]}),
        json!({"NetworkMode":format!("container:{unsafe_name}")}),
    ] {
        let (status, response) = api(
            &client,
            "POST",
            "/v1.45/containers/create",
            &json!({"Image":inputs.image,"HostConfig":host}),
        )
        .await;
        assert_eq!(status, 403, "{response}");
        assert!(response.contains("GATEWAY_DOCKER_RESOURCE_CONSTRAINT"));
    }
    let volume = format!("{prefix}-unsafe-volume");
    assert_eq!(operator(&inputs,root.as_path(),"POST","/v1.45/volumes/create",&json!({"Name":volume,"Driver":"local","DriverOpts":{"type":"none","o":"bind","device":"/"}})).await.0,201);
    let (status,response)=api(&client,"POST","/v1.45/containers/create",&json!({"Image":inputs.image,"HostConfig":{"Mounts":[{"Type":"volume","Source":volume,"Target":"/host"}]}})).await;
    assert_eq!(status, 403, "{response}");
    assert!(response.contains("GATEWAY_DOCKER_RESOURCE_CONSTRAINT"));
    assert_eq!(
        operator(
            &inputs,
            root.as_path(),
            "DELETE",
            &format!("/v1.45/volumes/{volume}"),
            &Value::Null
        )
        .await
        .0,
        204
    );
    let (status, privileged_exec) = operator(
        &inputs,
        root.as_path(),
        "POST",
        &format!("/v1.45/containers/{worker}/exec"),
        &json!({"Cmd":["touch","/data/privileged-exec"],"Privileged":true}),
    )
    .await;
    assert_eq!(status, 201);
    let exec_id = privileged_exec["Id"].as_str().unwrap();
    let (status, response) = api(
        &client,
        "POST",
        &format!("/v1.45/exec/{exec_id}/start"),
        &json!({"Detach":true,"Tty":false}),
    )
    .await;
    assert_eq!(status, 403, "{response}");
    assert!(response.contains("GATEWAY_DOCKER_RESOURCE_CONSTRAINT"));
    let (_, exec) = operator(
        &inputs,
        root.as_path(),
        "GET",
        &format!("/v1.45/exec/{exec_id}/json"),
        &Value::Null,
    )
    .await;
    assert_eq!(exec["Running"], false);
    assert_eq!(
        api(
            &client,
            "POST",
            "/v1.45/build?version=2&entitlements=security.insecure",
            &Value::Null
        )
        .await
        .0,
        403
    );
    assert_eq!(
        operator(
            &inputs,
            root.as_path(),
            "DELETE",
            &format!("/v1.45/containers/{unsafe_id}"),
            &Value::Null
        )
        .await
        .0,
        204
    );

    let expired_root = root.as_path().join("expired-instance");
    let expired = start(&expired_root, &inputs, true).await;
    assert!(
        api(
            &expired_root,
            "POST",
            &format!("/v1.45/containers/{worker}/exec"),
            &json!({"Cmd":["touch","/data/after-expiry"]})
        )
        .await
        .0 >= 400
    );
    expired.shutdown().await;
    assert!(
        run(
            &client,
            &[
                "exec",
                &worker,
                "sh",
                "-c",
                "test ! -e /data/after-expiry && cat /data/value"
            ]
        )
        .await
        .contains("retained")
    );
    let path = client.join("policy.toml");
    let mut policy: toml::Value = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    policy["agents"]["witness"]["services"]
        .as_table_mut()
        .unwrap()
        .remove("docker-proof");
    std::fs::write(&path, toml::to_string(&policy).unwrap()).unwrap();
    assert!(proxy.reload_policy_if_changed().await.unwrap());
    assert!(
        api(
            &client,
            "POST",
            &format!("/v1.45/containers/{worker}/exec"),
            &json!({"Cmd":["touch","/data/after-revocation"]})
        )
        .await
        .0 >= 400
    );
    let observer_root = root.as_path().join("observer-instance");
    let observer = start(&observer_root, &inputs, false).await;
    assert!(
        run(
            &observer_root,
            &[
                "exec",
                &worker,
                "sh",
                "-c",
                "test ! -e /data/after-revocation && cat /data/value"
            ]
        )
        .await
        .contains("retained")
    );
    run(
        &observer_root,
        &[
            "compose",
            "-p",
            &prefix,
            "-f",
            cf,
            "down",
            "--volumes",
            "--remove-orphans",
        ],
    )
    .await;
    run(&observer_root, &["image", "rm", &image]).await;
    assert_eq!(
        operator(
            &inputs,
            root.as_path(),
            "GET",
            &format!("/v1.45/containers/{web}/json"),
            &Value::Null
        )
        .await
        .0,
        404
    );
    observer.shutdown().await;
    proxy.shutdown().await;
    std::fs::remove_dir_all(&root).unwrap();
    println!(
        "Allowed lifecycle, pre-effect refusals, expiry/revocation and retained persistent data passed for {prefix}."
    );
}

/// Reuses the protected daemon, clients and TLS inputs from the transport and
/// workload witness. Run only this test for the project candidate.
#[tokio::test]
#[ignore = "requires the existing operator-owned Docker/Compose acceptance venue"]
async fn real_docker_project_lifecycle_and_identity() {
    let inputs = Inputs::read();
    let parent = PathBuf::from(
        std::env::var_os("SAFEYOLO_DOCKER_PROOF_ROOT")
            .expect("disk-backed owned scratch parent required"),
    );
    let root = tempfile::Builder::new()
        .prefix("docker-project-proof-")
        .tempdir_in(parent)
        .unwrap()
        .keep();
    let client = root.join("project-client");
    let prefix = format!(
        "syproject{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    println!(
        "Project proof owned prefix {prefix}; private scratch {}",
        root.display()
    );
    let (_, image) = operator(
        &inputs,
        &root,
        "GET",
        &format!("/v1.45/images/{}/json", inputs.image),
        &Value::Null,
    )
    .await;
    let image_id = image["Id"]
        .as_str()
        .expect("reuse the already prepared qualified Linux image")
        .to_owned();
    let volume_name = format!("{prefix}-ordinary-data");
    let (status, volume) = operator(
        &inputs,
        &root,
        "POST",
        "/v1.45/volumes/create",
        &json!({"Name":volume_name}),
    )
    .await;
    assert_eq!(status, 201);
    let mut networks = Vec::new();
    for suffix in ["ordinary-net", "shared-net", "beta-net"] {
        let (status, value) = operator(
            &inputs,
            &root,
            "POST",
            "/v1.45/networks/create",
            &json!({"Name":format!("{prefix}-{suffix}"),"Driver":"bridge"}),
        )
        .await;
        assert_eq!(status, 201);
        networks.push(value["Id"].as_str().unwrap().to_owned());
    }
    let ordinary = format!("{prefix}-ordinary");
    let beta = format!("{prefix}-unrelated");
    let mut containers = Vec::new();
    for (name, network) in [(&ordinary, &networks[0]), (&beta, &networks[2])] {
        let mut config = json!({"Image":image_id,"Cmd":["sh","-c","while :; do sleep 1; done"],"HostConfig":{"CgroupnsMode":"private","NetworkMode":network}});
        if name == &ordinary {
            config["HostConfig"]["Binds"] = json!([format!("{volume_name}:/data")]);
        }
        let (status, value) = operator(
            &inputs,
            &root,
            "POST",
            &format!("/v1.45/containers/create?name={name}"),
            &config,
        )
        .await;
        assert_eq!(status, 201);
        containers.push(value["Id"].as_str().unwrap().to_owned());
    }
    assert_eq!(
        operator(
            &inputs,
            &root,
            "POST",
            &format!("/v1.45/networks/{}/connect", networks[1]),
            &json!({"Container":containers[1]})
        )
        .await
        .0,
        200
    );
    let access = json!({"mode":"project","name":prefix,"adoption":"operator-selection-1","selected":{"containers":[containers[0]],"networks":[networks[0]],"volumes":{volume_name.clone():volume["CreatedAt"]}},"shared":{"images":[image_id],"networks":[networks[1]]}});
    let mut proxy = start_with_access(&client, &inputs, false, Some(access.clone())).await;
    println!("{}", run(&client, &["version"]).await);
    println!("{}", run(&client, &["compose", "version"]).await);
    run(&client, &["start", &ordinary]).await;
    run(
        &client,
        &[
            "exec",
            &ordinary,
            "sh",
            "-c",
            "echo project-data >/data/proof",
        ],
    )
    .await;
    for path in [
        "/v1.45/containers/json?all=true",
        "/v1.45/networks",
        "/v1.45/volumes",
        "/v1.45/images/json",
        "/v1.45/info",
    ] {
        let (status, body) = api(&client, "GET", path, &Value::Null).await;
        assert_eq!(status, 200, "{path}");
        assert!(
            !body.contains(&beta) && !body.contains(&containers[1]) && !body.contains(&networks[2]),
            "foreign metadata at {path}"
        );
    }
    let (_, body) = api(
        &client,
        "GET",
        &format!("/v1.45/networks/{}", networks[1]),
        &Value::Null,
    )
    .await;
    assert!(!body.contains(&beta) && !body.contains(&containers[1]));
    for id in [&containers[1], &beta, &"f".repeat(64)] {
        assert_eq!(
            api(
                &client,
                "GET",
                &format!("/v1.45/containers/{id}/json"),
                &Value::Null
            )
            .await
            .0,
            404
        );
        assert_eq!(
            api(
                &client,
                "POST",
                &format!("/v1.45/containers/{id}/start"),
                &Value::Null
            )
            .await
            .0,
            404
        );
    }
    let until = time::OffsetDateTime::now_utc().unix_timestamp() + 1;
    let (status, body) = api(
        &client,
        "GET",
        &format!("/v1.45/events?since=0&until={until}"),
        &Value::Null,
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        !body.contains(&beta) && !body.contains(&containers[1]) && !body.contains(&networks[2])
    );
    assert_eq!(
        api(
            &client,
            "GET",
            &format!("/v1.45/containers/{}/stats?stream=false", containers[1]),
            &Value::Null
        )
        .await
        .0,
        404
    );
    assert_eq!(
        api(
            &client,
            "POST",
            &format!("/v1.45/networks/{}/connect", networks[1]),
            &json!({"Container":containers[1]})
        )
        .await
        .0,
        404
    );
    for host in [
        json!({"NetworkMode":format!("container:{}",containers[1])}),
        json!({"VolumesFrom":[containers[1]]}),
        json!({"NetworkMode":networks[2]}),
    ] {
        let (status, _) = api(
            &client,
            "POST",
            "/v1.45/containers/create",
            &json!({"Image":image_id,"HostConfig":host}),
        )
        .await;
        assert_eq!(status, 404, "indirect project escape");
    }
    assert_eq!(
        api(
            &client,
            "DELETE",
            &format!("/v1.45/networks/{}", networks[1]),
            &Value::Null
        )
        .await
        .0,
        404
    );
    assert_eq!(
        api(
            &client,
            "DELETE",
            &format!("/v1.45/images/{image_id}"),
            &Value::Null
        )
        .await
        .0,
        404
    );
    let compose = root.join("project-compose.yaml");
    std::fs::write(&compose,format!("services:\n  app:\n    image: {image_id}\n    command: ['sh', '-c', 'echo project-started; while :; do sleep 1; done']\n    volumes: ['state:/data']\nvolumes:\n  state: {{}}\n")).unwrap();
    let cf = compose.to_str().unwrap();
    run(&client, &["compose", "-p", &prefix, "-f", cf, "up", "-d"]).await;
    assert!(
        run(&client, &["compose", "-p", &prefix, "-f", cf, "logs"])
            .await
            .contains("project-started")
    );
    run(
        &client,
        &[
            "compose",
            "-p",
            &prefix,
            "-f",
            cf,
            "exec",
            "-T",
            "app",
            "sh",
            "-c",
            "echo persistent >/data/value",
        ],
    )
    .await;
    run(
        &client,
        &[
            "compose",
            "-p",
            &prefix,
            "-f",
            cf,
            "up",
            "-d",
            "--force-recreate",
        ],
    )
    .await;
    assert!(
        run(
            &client,
            &[
                "compose",
                "-p",
                &prefix,
                "-f",
                cf,
                "exec",
                "-T",
                "app",
                "cat",
                "/data/value"
            ]
        )
        .await
        .contains("persistent")
    );
    let renamed = format!("{prefix}-renamed");
    assert_eq!(
        operator(
            &inputs,
            &root,
            "POST",
            &format!("/v1.45/containers/{}/rename?name={renamed}", containers[0]),
            &Value::Null
        )
        .await
        .0,
        204
    );
    let (status,replacement)=operator(&inputs,&root,"POST",&format!("/v1.45/containers/create?name={ordinary}"),&json!({"Image":image_id,"Labels":{"com.docker.compose.project":prefix},"HostConfig":{"CgroupnsMode":"private","NetworkMode":networks[2]}})).await;
    assert_eq!(status, 201);
    containers.push(replacement["Id"].as_str().unwrap().into());
    assert_eq!(
        api(
            &client,
            "GET",
            &format!("/v1.45/containers/{ordinary}/json"),
            &Value::Null
        )
        .await
        .0,
        404
    );
    assert_eq!(
        api(
            &client,
            "GET",
            &format!("/v1.45/containers/{renamed}/json"),
            &Value::Null
        )
        .await
        .0,
        200
    );
    run(&client, &["update", "--cpus", "0.5", &renamed]).await;
    proxy.shutdown().await;
    proxy = start_with_access(&client, &inputs, false, Some(access.clone())).await;
    assert!(
        run(&client, &["exec", &renamed, "cat", "/data/proof"])
            .await
            .contains("project-data")
    );
    run(&client, &["compose", "-p", &prefix, "-f", cf, "stop"]).await;
    run(&client, &["compose", "-p", &prefix, "-f", cf, "start"]).await;
    run(
        &client,
        &["compose", "-p", &prefix, "-f", cf, "down", "--volumes"],
    )
    .await;
    // Removing the selected container permits the second administrator to
    // replace its ordinary volume name, even with the same client labels.
    run(&client, &["rm", "-f", &renamed]).await;
    assert_eq!(
        operator(
            &inputs,
            &root,
            "DELETE",
            &format!("/v1.45/volumes/{volume_name}"),
            &Value::Null
        )
        .await
        .0,
        204
    );
    let (status, new_volume) = operator(
        &inputs,
        &root,
        "POST",
        "/v1.45/volumes/create",
        &json!({"Name":volume_name,"Labels":{"com.docker.compose.project":prefix}}),
    )
    .await;
    assert_eq!(status, 201);
    assert_eq!(
        api(
            &client,
            "GET",
            &format!("/v1.45/volumes/{volume_name}"),
            &Value::Null
        )
        .await
        .0,
        404
    );
    proxy.shutdown().await;
    let mut readopt = access;
    readopt["adoption"] = json!("explicit-operator-readoption-2");
    readopt["selected"]["volumes"][&volume_name] = new_volume["CreatedAt"].clone();
    proxy = start_with_access(&client, &inputs, false, Some(readopt)).await;
    assert_eq!(
        api(
            &client,
            "GET",
            &format!("/v1.45/volumes/{volume_name}"),
            &Value::Null
        )
        .await
        .0,
        200
    );
    // Cleanup uses only this run's exact returned IDs and the verified volume.
    proxy.shutdown().await;
    for id in &containers[1..] {
        assert_eq!(
            operator(
                &inputs,
                &root,
                "DELETE",
                &format!("/v1.45/containers/{id}?force=true"),
                &Value::Null
            )
            .await
            .0,
            204
        );
    }
    for id in &networks {
        assert_eq!(
            operator(
                &inputs,
                &root,
                "DELETE",
                &format!("/v1.45/networks/{id}"),
                &Value::Null
            )
            .await
            .0,
            204
        );
    }
    assert_eq!(
        operator(
            &inputs,
            &root,
            "DELETE",
            &format!("/v1.45/volumes/{volume_name}"),
            &Value::Null
        )
        .await
        .0,
        204
    );
    std::fs::remove_dir_all(&root).unwrap();
    println!(
        "Project lifecycle, visibility, indirect references, co-administrator changes, restart and readoption passed for {prefix}. The controlled proxy-wire test supplies interrupted-creation reconciliation."
    );
}
