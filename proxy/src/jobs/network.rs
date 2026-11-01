//! A host caller holds one temporary listener on the existing proxy. Closing
//! the management connection revokes it; no configured agent or grant is added.

use crate::{Error, RuntimeState, admin_api, credentials::Secret, native_client};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, body::Incoming};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

const ROUTE: &str = "/admin/jobs/delegate";
const PROTOCOL: &str = "safeyolo-job";
const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub(crate) struct Authority {
    pub principal: String,
    pub run: crate::host_runs::AgentRun,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Delegation {
    gate_id: String,
    run_id: String,
    socket_path: PathBuf,
}

impl Delegation {
    fn authority(&self) -> Result<Authority, Error> {
        if self.gate_id.is_empty()
            || self.run_id.len() != 32
            || !self.run_id.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("job delegation requires a gate ID and a 32-digit run ID".into());
        }
        let name = format!("job-{}", self.run_id);
        Ok(Authority {
            principal: format!("gate:{}", self.gate_id),
            run: crate::host_runs::AgentRun {
                agent: name.clone(),
                agent_id: name,
                run_id: self.run_id.clone(),
            },
        })
    }
}

pub(crate) fn route(path: &str) -> bool {
    path == ROUTE
}

fn response(status: StatusCode, body: String) -> Response<admin_api::AdminBody> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(
            Full::new(Bytes::from(body))
                .map_err(|never| match never {})
                .boxed(),
        )
        .expect("fixed job response")
}

/// Only the authenticated management listener calls this. The host selects
/// the socket and stable gate; neither is taken from guest HTTP metadata.
pub(crate) async fn serve(
    mut request: Request<Incoming>,
    state: RuntimeState,
    token: &str,
    mut stop: tokio::sync::watch::Receiver<bool>,
    tasks: &crate::admin_listener::EventTasks,
) -> Result<Response<admin_api::AdminBody>, admin_api::Error> {
    let runtime = state
        .read()
        .map_err(|_| admin_api::Error::RegistryUnavailable)?
        .clone();
    if !admin_api::authenticate(request.headers(), token)? {
        return Ok(admin_api::unauthorized()
            .submit_audit(&runtime.audit, "host", ROUTE)?
            .into_response());
    }
    if request.method() != hyper::Method::POST
        || request
            .headers()
            .get("upgrade")
            .is_none_or(|v| v != PROTOCOL)
        || !request.headers().get_all("connection").iter().any(|v| {
            v.to_str().is_ok_and(|v| {
                v.split(',')
                    .any(|v| v.trim().eq_ignore_ascii_case("upgrade"))
            })
        })
    {
        return Ok(response(
            StatusCode::BAD_REQUEST,
            json!({"error":"job delegation requires a management connection upgrade"}).to_string(),
        ));
    }
    let upgrade = hyper::upgrade::on(&mut request);
    let body = request
        .into_body()
        .collect()
        .await
        .map_err(|_| admin_api::Error::BodyRead)?
        .to_bytes();
    let prepared = (|| -> Result<_, Error> {
        let delegation: Delegation = serde_json::from_slice(&body)?;
        let authority = delegation.authority()?;
        let tokens = runtime
            .policy
            .as_ref()
            .and_then(|policy| policy.gateway())
            .ok_or("gateway policy is unavailable")?
            .agent_environment_json(&authority.principal)?;
        let (listener, socket) = crate::SocketPath::bind(&delegation.socket_path)?;
        fs::set_permissions(&delegation.socket_path, fs::Permissions::from_mode(0o600))?;
        let listener = crate::RunningListener::start_with_job(
            listener,
            socket,
            crate::AgentListener {
                agent_id: authority.run.agent.clone(),
                socket_path: delegation.socket_path,
                source_id: None,
            },
            state,
            Arc::default(),
            Some(authority),
        );
        Ok((listener, tokens))
    })();
    let (listener, tokens) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":error.to_string()}).to_string(),
            ));
        }
    };
    crate::admin_listener::spawn_event_task(tasks, async move {
        if let Ok(upgraded) = upgrade.await {
            let mut stream = TokioIo::new(upgraded);
            let sent = async {
                stream
                    .write_u64(tokens.expose_secret().len().try_into()?)
                    .await?;
                stream.write_all(tokens.expose_secret().as_bytes()).await?;
                Ok::<_, Error>(())
            };
            if matches!(tokio::time::timeout(TIMEOUT, sent).await, Ok(Ok(()))) {
                tokio::select! {
                    _ = stream.read_u8() => {},
                    _ = stop.changed() => {},
                }
            }
            // Join accepted requests before acknowledging revocation. Reuse
            // normal listener teardown, including cancellation of open tunnels.
            if listener.stop().await.is_ok() {
                let _ = tokio::time::timeout(TIMEOUT, stream.write_u8(0)).await;
            }
        } else {
            let _ = listener.stop().await;
        }
    })
    .await;
    Ok(Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("connection", "upgrade")
        .header("upgrade", PROTOCOL)
        .body(
            Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed(),
        )
        .expect("fixed job upgrade"))
}

pub(super) struct Client {
    stream: TokioIo<hyper::upgrade::Upgraded>,
    tokens: Secret,
}

impl Client {
    pub async fn connect(
        config: &Path,
        directory: &Path,
        spec: &super::JobSpec,
        run_id: &str,
    ) -> Result<Self, Error> {
        let path = directory.join("proxy");
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        let delegation = Delegation {
            gate_id: spec.gate_id.clone(),
            run_id: run_id.into(),
            socket_path: path.join("proxy.sock"),
        };
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::ffi::OsStrExt;
            if delegation.socket_path.as_os_str().as_bytes().len() + 1 > 104 {
                return Err(format!(
                    "job socket path exceeds the 104-byte platform limit: {}; use a shorter TMPDIR",
                    delegation.socket_path.display()
                )
                .into());
            }
        }
        let client = Self::open(config, &delegation).await?;
        // runsc's Gofer uses the selected root mapping for host UDS connects.
        // Only this fresh listener directory/socket acquire guest access.
        #[cfg(target_os = "linux")]
        {
            let access = async {
                let mapping = crate::host_platform::in_config(config.to_owned(), async {
                    crate::linux_host::selected_mapping()
                })
                .await?;
                for (target, mode) in [(&path, "rx"), (&delegation.socket_path, "rw")] {
                    let status = tokio::process::Command::new("setfacl")
                        .args(["-m", &format!("u:{}:{mode}", mapping.uid_base)])
                        .arg(target)
                        .status()
                        .await?;
                    if !status.success() {
                        return Err(
                            "could not grant the selected job mapping access to its proxy socket"
                                .into(),
                        );
                    }
                }
                Ok::<_, Error>(())
            }
            .await;
            if let Err(error) = access {
                if let Err(cleanup) = client.close().await {
                    return Err(format!("{error}; job delegation cleanup failed: {cleanup}").into());
                }
                return Err(error);
            }
        }
        Ok(client)
    }

    async fn open(config: &Path, delegation: &Delegation) -> Result<Self, Error> {
        let client = tokio::time::timeout(TIMEOUT, async {
            let (socket, host, token) = native_client::operator_socket(config).await?;
            let (mut client, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(socket)).await?;
            let driver = tokio::spawn(connection.with_upgrades());
            let request = Request::builder()
                .method(hyper::Method::POST)
                .uri(ROUTE)
                .header("host", host)
                .header("authorization", format!("Bearer {}", token.trim()))
                .header("connection", "upgrade")
                .header("upgrade", PROTOCOL)
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(serde_json::to_vec(delegation)?)))?;
            let mut response = client.send_request(request).await?;
            if response.status() != StatusCode::SWITCHING_PROTOCOLS {
                let status = response.status();
                let body = response.into_body().collect().await?.to_bytes();
                driver.abort();
                return Err(format!(
                    "job delegation {status}: {}",
                    String::from_utf8_lossy(&body)
                )
                .into());
            }
            let mut stream = TokioIo::new(hyper::upgrade::on(&mut response).await?);
            let size: usize = stream.read_u64().await?.try_into()?;
            let mut bytes = Zeroizing::new(vec![0; size]);
            stream.read_exact(&mut bytes).await?;
            Ok::<_, Error>(Self {
                stream,
                tokens: Secret::new(String::from_utf8(bytes.to_vec())?),
            })
        })
        .await??;
        Ok(client)
    }

    pub fn environment(&self) -> Vec<String> {
        let mut env = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]
            .map(|name| format!("{name}=http://127.0.0.1:8080"))
            .to_vec();
        env.extend(
            ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"]
                .map(|name| format!("{name}=/safeyolo/network/mitmproxy-ca-cert.pem")),
        );
        env.push(format!(
            "SAFEYOLO_GATEWAY_TOKENS={}",
            self.tokens.expose_secret()
        ));
        env
    }

    pub async fn close(mut self) -> Result<(), Error> {
        tokio::time::timeout(TIMEOUT, async {
            self.stream.write_u8(0).await?;
            if self.stream.read_u8().await? != 0 {
                return Err("job delegation cleanup acknowledgment is invalid".into());
            }
            Ok::<_, Error>(())
        })
        .await?
    }
}

pub(super) fn stage(share: &Path, host: &Path, installation: &Path) -> Result<(), Error> {
    let directory = share.join("network");
    fs::create_dir(&directory)?;
    fs::copy(
        host.join("assets/guest/guest-proxy-forwarder"),
        directory.join("guest-proxy-forwarder"),
    )?;
    fs::copy(
        installation.join("certs/mitmproxy-ca-cert.pem"),
        directory.join("mitmproxy-ca-cert.pem"),
    )?;
    fs::write(
        directory.join("start"),
        concat!(
            "/safeyolo/network/guest-proxy-forwarder >/run/job-proxy.log 2>&1 &\n",
            "job_forwarder=$!\n",
            "until ss -ltnH 'sport = :8080' | grep -q .; do\n",
            "    kill -0 \"$job_forwarder\"\n",
            "    sleep 0.01\n",
            "done\n",
        ),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{Credential, Secret};
    use tokio::net::{TcpListener, UnixStream};

    fn config(root: &Path, port: u16) -> PathBuf {
        for dir in ["data", "builtin-services", "services"] {
            fs::create_dir(root.join(dir)).unwrap();
        }
        fs::write(root.join("data/admin_token"), "test-host-token").unwrap();
        fs::write(root.join("data/agent_token"), "test-agent-token").unwrap();
        fs::write(root.join("services/simple.yaml"), "schema_version: 1\nname: simple\ndefault_host: 127.0.0.1\nauth: {type: bearer, allow_http: true}\ncapabilities:\n  reader:\n    routes:\n      - methods: [GET]\n        path: /value\n").unwrap();
        fs::write(
            root.join("policy.toml"),
            format!(
                r#"
[hosts."127.0.0.1"]
service = "simple"
[hosts."127.0.0.1:{port}"]
egress = "allow"
[hosts."*"]
egress = "deny"
[agents."gate:proof".services.simple]
capability = "reader"
token = "job-secret"
[controls.credentials]
enabled = false
[controls.patterns]
enabled = false
[controls.test_context]
action = "warn"
"#
            ),
        )
        .unwrap();
        let path = root.join("config.toml");
        fs::write(
            &path,
            "admin_port = 0\nlisteners = []\nflow_store_enabled = false\n",
        )
        .unwrap();
        crate::credentials::open(&root.join("data"))
            .unwrap()
            .store(Credential::new(
                "job-secret",
                "bearer",
                Secret::new("synthetic-job-provider-secret"),
            ))
            .unwrap();
        path
    }

    async fn get(path: &Path, target: &str, token: &str) -> String {
        let mut stream = UnixStream::connect(path).await.unwrap();
        stream.write_all(format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {token}\r\nX-SafeYolo-Agent: gate:proof\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut response = String::new();
        tokio::time::timeout(TIMEOUT, stream.read_to_string(&mut response))
            .await
            .unwrap()
            .unwrap();
        response
    }

    #[tokio::test]
    async fn saved_gate_capabilities_share_the_proxy_and_end_with_each_host_connection() {
        let root = tempfile::tempdir().unwrap();
        let origin = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = origin.local_addr().unwrap().port();
        let path = config(root.path(), port);
        let before_policy = fs::read(root.path().join("policy.toml")).unwrap();
        let before_config = fs::read(&path).unwrap();
        let proxy = crate::Proxy::start(crate::native_config::read(&path).unwrap())
            .await
            .unwrap();
        let sink = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = origin.accept().await.unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    header.push(stream.read_u8().await.unwrap());
                }
                let header = String::from_utf8(header).unwrap().to_ascii_lowercase();
                assert!(
                    header.contains("authorization: bearer synthetic-job-provider-secret\r\n"),
                    "{header}"
                );
                assert!(!header.contains("sgw_"));
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .unwrap();
            }
        });
        let mut prior_token = None;
        let mut run_names = Vec::new();
        for index in 0..2 {
            let run_id = format!("{index:032x}");
            run_names.push(format!("job-{run_id}"));
            let delegation = Delegation {
                gate_id: "proof".into(),
                run_id,
                socket_path: root.path().join(format!("{index}.sock")),
            };
            let client = Client::open(&path, &delegation).await.unwrap();
            let tokens: serde_json::Value =
                serde_json::from_str(client.tokens.expose_secret()).unwrap();
            let token = tokens["simple"].as_str().unwrap().to_owned();
            if let Some(prior) = &prior_token {
                assert_eq!(&token, prior);
            }
            prior_token = Some(token.clone());
            let target = format!("http://127.0.0.1:{port}/value");
            assert!(
                get(&delegation.socket_path, &target, &token)
                    .await
                    .starts_with("HTTP/1.1 200")
            );
            let api = get(
                &delegation.socket_path,
                "http://_safeyolo.proxy.internal/health",
                "test-agent-token",
            )
            .await;
            assert!(!api.starts_with("HTTP/1.1 200"), "{api}");
            assert!(
                !get(
                    &delegation.socket_path,
                    &format!("http://127.0.0.1:{port}/write"),
                    &token
                )
                .await
                .starts_with("HTTP/1.1 200")
            );
            let other = Delegation {
                gate_id: "other".into(),
                run_id: format!("{:032x}", index + 10),
                socket_path: root.path().join(format!("other{index}.sock")),
            };
            let thief = Client::open(&path, &other).await.unwrap();
            assert_eq!(thief.tokens.expose_secret(), "{}");
            assert!(
                !get(&other.socket_path, &target, &token)
                    .await
                    .starts_with("HTTP/1.1 200")
            );
            thief.close().await.unwrap();
            assert!(!other.socket_path.exists());
            client.close().await.unwrap();
            assert!(!delegation.socket_path.exists());
        }
        tokio::time::timeout(TIMEOUT, sink).await.unwrap().unwrap();
        // Dropping an abandoned host session revokes its listener, too.
        let abandoned = Delegation {
            gate_id: "proof".into(),
            run_id: "a".repeat(32),
            socket_path: root.path().join("abandoned.sock"),
        };
        drop(Client::open(&path, &abandoned).await.unwrap());
        tokio::time::timeout(TIMEOUT, async {
            while abandoned.socket_path.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        proxy.shutdown().await;
        assert_eq!(
            fs::read(root.path().join("policy.toml")).unwrap(),
            before_policy
        );
        assert_eq!(fs::read(&path).unwrap(), before_config);
        let rows: Vec<serde_json::Value> = fs::read_to_string(root.path().join("logs/audit.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        for run in run_names {
            assert!(rows.iter().any(
                |row| row["details"]["attribution"]["trusted_transport_identity"] == run
                    && row["details"]["attribution"]["attribution_provenance"]["authorization_principal"]
                        == "gate:proof"
            ));
        }
    }

    #[test]
    fn delegated_identity_uses_one_exact_principal_without_agent_run_authority() {
        let authority = Delegation {
            gate_id: "proof with spaces ".into(),
            run_id: "a".repeat(32),
            socket_path: "/unused".into(),
        }
        .authority()
        .unwrap();
        let identity = crate::ConnectionIdentity {
            agent_id: authority.run.agent.clone(),
            authorization_principal: Some(authority.principal.clone()),
            run: Some(authority.run),
            connection_id: "owned".into(),
            source_id: None,
            ingress_binding: None,
        };
        assert_eq!(identity.request_agent(), Some("gate:proof with spaces "));
        assert_eq!(
            identity.request_identity().agent(),
            identity.request_agent()
        );
        assert!(identity.request_identity().run().is_none());
        assert!(identity.current_agent_run().is_none());
    }

    #[tokio::test]
    async fn rejected_delegations_preserve_paths_and_require_host_authentication() {
        let root = tempfile::tempdir().unwrap();
        let path = config(root.path(), 12345);
        let proxy = crate::Proxy::start(crate::native_config::read(&path).unwrap())
            .await
            .unwrap();
        let mut delegation = Delegation {
            gate_id: "proof".into(),
            run_id: "b".repeat(32),
            socket_path: root.path().join("candidate.sock"),
        };
        fs::write(root.path().join("data/admin_token"), "test-agent-token").unwrap();
        let error = match Client::open(&path, &delegation).await {
            Err(error) => error,
            Ok(_) => panic!("agent token delegated a job"),
        };
        assert!(error.to_string().contains("401"));
        assert!(!delegation.socket_path.exists());
        fs::write(root.path().join("data/admin_token"), "test-host-token").unwrap();
        delegation.run_id = "invalid".into();
        assert!(Client::open(&path, &delegation).await.is_err());
        assert!(!delegation.socket_path.exists());
        delegation.run_id = "b".repeat(32);
        fs::write(&delegation.socket_path, "protected ordinary file").unwrap();
        assert!(Client::open(&path, &delegation).await.is_err());
        assert_eq!(
            fs::read_to_string(&delegation.socket_path).unwrap(),
            "protected ordinary file"
        );
        proxy.shutdown().await;
    }
}
