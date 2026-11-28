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
    collections::BTreeMap,
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
    pub checks: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Delegation {
    gate_id: String,
    run_id: String,
    socket_path: PathBuf,
    #[serde(default)]
    checks: Vec<String>,
    #[serde(default)]
    bind_policy: bool,
}

#[derive(Serialize, Deserialize)]
struct Session {
    tokens: serde_json::Value,
    service_auth: BTreeMap<String, crate::services::AuthConfig>,
    policy_hash: String,
    configuration_sha256: String,
}

pub(super) type ServiceHeaders = BTreeMap<String, (String, Secret)>;

fn same_policy(state: &RuntimeState, runtime: &crate::Runtime) -> bool {
    state
        .read()
        .is_ok_and(|current| match (&current.policy, &runtime.policy) {
            (Some(current), Some(expected)) => Arc::ptr_eq(current, expected),
            _ => false,
        })
}

pub(crate) async fn wait_policy_change(state: &RuntimeState, runtime: &crate::Runtime) {
    let mut changes = tokio::time::interval(Duration::from_millis(25));
    loop {
        changes.tick().await;
        if !same_policy(state, runtime) {
            return;
        }
    }
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
            checks: self.checks.clone(),
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
    tasks: &crate::admin_listener::ListenerTasks,
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
        let gateway = runtime
            .policy
            .as_ref()
            .and_then(|policy| policy.gateway())
            .ok_or("gateway policy is unavailable")?;
        let tokens = gateway.agent_environment_json(&authority.principal)?;
        let tokens: serde_json::Value = serde_json::from_str(tokens.expose_secret())?;
        let service_auth = gateway.registry().map_or_else(BTreeMap::new, |registry| {
            registry
                .services
                .iter()
                .filter(|(name, _)| tokens.get(*name).is_some())
                .filter_map(|(name, service)| {
                    service
                        .auth
                        .as_ref()
                        .map(|auth| (name.clone(), auth.clone()))
                })
                .collect()
        });
        let session = Zeroizing::new(serde_json::to_vec(&Session {
            tokens,
            service_auth,
            policy_hash: runtime
                .policy
                .as_ref()
                .ok_or("policy unavailable")?
                .policy_hash(),
            configuration_sha256: super::digest(&serde_json::to_vec(&runtime.config)?),
        })?);
        let listener = start_listener(state.clone(), &delegation, authority)?;
        Ok((listener, session, delegation.bind_policy))
    })();
    let (listener, session, bind_policy) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":error.to_string()}).to_string(),
            ));
        }
    };
    crate::admin_listener::spawn_listener_task(tasks, async move {
        if let Ok(upgraded) = upgrade.await {
            let mut stream = TokioIo::new(upgraded);
            let sent = async {
                stream
                    .write_u64(session.len().try_into()?)
                    .await?;
                stream.write_all(&session).await?;
                Ok::<_, Error>(())
            };
            if matches!(tokio::time::timeout(TIMEOUT, sent).await, Ok(Ok(()))) {
                let mut changes = tokio::time::interval(Duration::from_millis(25));
                loop {
                    tokio::select! {
                        command = stream.read_u8() => {
                            if !matches!(command, Ok(1)) || bind_policy && !state.read().is_ok_and(|current| Arc::ptr_eq(&current, &runtime)) {
                                break;
                            }
                            if stream.write_u8(1).await.is_err() { break; }
                        },
                        _ = changes.tick(), if bind_policy => {
                            if !state.read().is_ok_and(|current| Arc::ptr_eq(&current, &runtime)) { break; }
                        },
                        _ = stop.changed() => break,
                    }
                }
            }
            // Job listener teardown cancels accepted transports immediately,
            // then joins them before acknowledging revocation.
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

fn start_listener(
    state: RuntimeState,
    delegation: &Delegation,
    authority: Authority,
) -> Result<crate::RunningListener, Error> {
    let (listener, socket) = crate::SocketPath::bind(&delegation.socket_path)?;
    fs::set_permissions(&delegation.socket_path, fs::Permissions::from_mode(0o600))?;
    Ok(crate::RunningListener::start_with_job(
        listener,
        socket,
        crate::AgentListener {
            agent_id: authority.run.agent.clone(),
            socket_path: delegation.socket_path.clone(),
            source_id: None,
        },
        state,
        Arc::default(),
        Some(authority),
    ))
}

/// Native policy collection owns this ephemeral delegation just as the host job
/// caller owns its management connection. It creates no agent or saved grant.
pub(crate) fn local(
    state: RuntimeState,
    gate_id: &str,
    checks: Vec<String>,
    socket_path: &Path,
) -> Result<(crate::RunningListener, Authority), Error> {
    let delegation = Delegation {
        gate_id: gate_id.into(),
        run_id: uuid::Uuid::new_v4().simple().to_string(),
        socket_path: socket_path.into(),
        checks,
        bind_policy: false,
    };
    let authority = delegation.authority()?;
    Ok((
        start_listener(state, &delegation, authority.clone())?,
        authority,
    ))
}

pub(super) struct Client {
    stream: TokioIo<hyper::upgrade::Upgraded>,
    tokens: Secret,
    service_auth: BTreeMap<String, crate::services::AuthConfig>,
    socket_path: PathBuf,
    pub(super) policy_hash: String,
    pub(super) configuration_sha256: String,
    revoked: bool,
    cleanup_confirmed: bool,
    confirmation_pending: bool,
}

impl Client {
    pub(crate) async fn connect_with_checks(
        config: &Path,
        directory: &Path,
        spec: &super::JobSpec,
        run_id: &str,
        checks: &[String],
    ) -> Result<Self, Error> {
        let path = directory.join("proxy");
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        let delegation = Delegation {
            gate_id: spec.gate_id.clone(),
            run_id: run_id.into(),
            socket_path: path.join("proxy.sock"),
            checks: checks.to_vec(),
            bind_policy: true,
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
            if size > 1024 * 1024 {
                return Err("job delegation metadata limit exceeded".into());
            }
            let mut bytes = Zeroizing::new(vec![0; size]);
            stream.read_exact(&mut bytes).await?;
            let session: Session = serde_json::from_slice(&bytes)?;
            Ok::<_, Error>(Self {
                stream,
                tokens: Secret::new(serde_json::to_string(&session.tokens)?),
                service_auth: session.service_auth,
                socket_path: delegation.socket_path.clone(),
                policy_hash: session.policy_hash,
                configuration_sha256: session.configuration_sha256,
                revoked: false,
                cleanup_confirmed: false,
                confirmation_pending: false,
            })
        })
        .await??;
        Ok(client)
    }

    pub(super) async fn connect_mediated(
        config: &Path,
        directory: &Path,
        spec: &super::JobSpec,
        run_id: &str,
        checks: &[String],
    ) -> Result<Self, Error> {
        // Only the host helper reaches this socket. Do not grant a guest UID
        // access or invoke the platform engine's Gofer/ACL setup.
        Self::open(
            config,
            &Delegation {
                gate_id: spec.gate_id.clone(),
                run_id: run_id.into(),
                socket_path: directory.join("p.sock"),
                checks: checks.to_vec(),
                bind_policy: true,
            },
        )
        .await
    }

    pub(super) fn service_access(&self) -> Result<(PathBuf, ServiceHeaders), Error> {
        let tokens: BTreeMap<String, String> = serde_json::from_str(self.tokens.expose_secret())?;
        Ok((
            self.socket_path.clone(),
            tokens
                .into_iter()
                .map(|(name, token)| {
                    let header =
                        crate::services::gateway_token_header(self.service_auth.get(&name), &token);
                    (name, header)
                })
                .collect(),
        ))
    }

    pub(super) async fn revoked(&mut self) {
        self.cleanup_confirmed = matches!(self.stream.read_u8().await, Ok(0));
        self.revoked = true;
    }

    pub(super) async fn confirm_current(&mut self) -> Result<(), Error> {
        if self.revoked {
            return Err("job delegation revoked".into());
        }
        // A deadline can cancel this future after its request was sent but
        // before its reply was consumed. Keep that reply distinct from the
        // listener's terminal cleanup acknowledgment in close().
        self.confirmation_pending = true;
        self.stream.write_u8(1).await?;
        let reply = self.stream.read_u8().await?;
        self.confirmation_pending = false;
        if reply != 1 {
            self.revoked = true;
            self.cleanup_confirmed = reply == 0;
            return Err("job policy changed or delegation revoked".into());
        }
        Ok(())
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
        if self.revoked {
            return if self.cleanup_confirmed {
                Ok(())
            } else {
                Err("delegated listener cleanup acknowledgment is unavailable".into())
            };
        }
        tokio::time::timeout(TIMEOUT, async {
            // A policy change can already have closed the management peer.
            // Its terminal acknowledgment still proves listener cleanup.
            let _ = self.stream.write_u8(0).await;
            let mut reply = self.stream.read_u8().await?;
            if self.confirmation_pending && reply == 1 {
                reply = self.stream.read_u8().await?;
            }
            if reply != 0 {
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
pub(super) mod tests {
    use super::*;
    use crate::credentials::{Credential, Secret};
    use tokio::net::{TcpListener, UnixStream};

    pub(in crate::jobs) fn config(root: &Path, port: u16) -> PathBuf {
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
        let uri: hyper::Uri = target.parse().unwrap();
        let host = uri.authority().unwrap();
        stream.write_all(format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\nX-SafeYolo-Agent: gate:proof\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut response = String::new();
        // Bound the observer even if a broken transport fails to terminate.
        tokio::time::timeout(TIMEOUT * 2, stream.read_to_string(&mut response))
            .await
            .unwrap()
            .unwrap();
        response
    }

    #[tokio::test]
    async fn cancelled_authority_confirmation_still_waits_for_listener_cleanup() {
        let root = tempfile::tempdir().unwrap();
        let path = config(root.path(), 1);
        let proxy = crate::Proxy::start(crate::native_config::read(&path).unwrap())
            .await
            .unwrap();
        let delegation = Delegation {
            gate_id: "proof".into(),
            run_id: "a".repeat(32),
            socket_path: root.path().join("cancelled-confirmation.sock"),
            checks: Vec::new(),
            bind_policy: true,
        };
        let mut client = Client::open(&path, &delegation).await.unwrap();
        // Poll the real confirmation until it waits for its reply, then drop
        // it like Hyperlight's outer deadline/select. The current-thread test
        // keeps the proxy from answering within that first poll.
        let mut confirmation = Box::pin(client.confirm_current());
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(confirmation.as_mut(), context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(confirmation);
        client.close().await.unwrap();
        assert!(!delegation.socket_path.exists());
        proxy.shutdown().await;
    }

    #[tokio::test]
    async fn platform_policy_revocation_closes_an_in_flight_response() {
        let root = tempfile::tempdir().unwrap();
        let origin = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = origin.local_addr().unwrap().port();
        let path = config(root.path(), port);
        let mut proxy = crate::Proxy::start(crate::native_config::read(&path).unwrap())
            .await
            .unwrap();
        let directory = root.path().join("platform-job");
        fs::create_dir(&directory).unwrap();
        let spec = serde_json::from_value(json!({
            "gate_id":"proof", "argv":["/bin/true"], "network":true,
            "timeout_seconds":30, "max_input_bytes":0,
            "max_input_entries":1, "retain_bytes":1024
        }))
        .unwrap();
        let mut client =
            Client::connect_with_checks(&path, &directory, &spec, &"a".repeat(32), &[])
                .await
                .unwrap();
        let endpoint = directory.join("proxy/proxy.sock");
        let tokens: serde_json::Value =
            serde_json::from_str(client.tokens.expose_secret()).unwrap();
        let token = tokens["simple"].as_str().unwrap().to_owned();
        let target = format!("http://127.0.0.1:{port}/value");
        let request_endpoint = endpoint.clone();
        let pending = tokio::spawn(async move { get(&request_endpoint, &target, &token).await });
        let (mut upstream, _) = origin.accept().await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(upstream.read_u8().await.unwrap());
        }
        assert!(
            String::from_utf8(header)
                .unwrap()
                .contains("synthetic-job-provider-secret")
        );
        let policy = root.path().join("policy.toml");
        fs::write(
            &policy,
            fs::read_to_string(&policy)
                .unwrap()
                .replace("egress = \"allow\"", "egress = \"deny\""),
        )
        .unwrap();
        assert!(proxy.reload_policy_if_changed().await.unwrap());
        // Socket removal marks shutdown admission. Offer the held response
        // during teardown, rather than waiting out a graceful-drain window.
        tokio::time::timeout(TIMEOUT, async {
            while endpoint.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let _ = upstream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nlate")
            .await;
        let response = pending.await.unwrap();
        assert!(!response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(!response.contains("late"), "{response}");
        assert!(client.confirm_current().await.is_err());
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(TIMEOUT * 2, upstream.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        client.close().await.unwrap();
        assert!(!endpoint.exists());
        proxy.shutdown().await;
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
                checks: Vec::new(),
                bind_policy: false,
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
            assert!(api.starts_with("HTTP/1.1 503"), "{api}");
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
                checks: Vec::new(),
                bind_policy: false,
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
            checks: Vec::new(),
            bind_policy: false,
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
            checks: Vec::new(),
            bind_policy: false,
        }
        .authority()
        .unwrap();
        let identity = crate::ConnectionIdentity {
            agent_id: authority.run.agent.clone(),
            authorization_principal: Some(authority.principal.clone()),
            policy_checks: Vec::new(),
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
            checks: Vec::new(),
            bind_policy: false,
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
