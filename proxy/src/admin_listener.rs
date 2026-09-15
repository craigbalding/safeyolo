//! Startup-owned operator listener, separate from trusted per-agent ingress.

use std::{
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};

use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::json;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
    task::{JoinHandle, JoinSet},
};
use zeroize::Zeroizing;

use crate::{Config, Error, RuntimeState, admin_api, policy::python_whitespace};

pub(crate) struct Prepared {
    listener: TcpListener,
    token: Arc<Zeroizing<String>>,
    address: SocketAddr,
}

impl Prepared {
    pub(crate) async fn bind(config: &Config) -> Result<Option<Self>, Error> {
        let Some(port) = config.admin_port else {
            return Ok(None);
        };
        let token = Arc::new(read_token(config.admin_api_token_file.as_deref())?);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
        let address = listener.local_addr()?;
        Ok(Some(Self {
            listener,
            token,
            address,
        }))
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) fn start(self, state: RuntimeState) -> Running {
        let (stop, receiver) = watch::channel(false);
        Running {
            address: self.address,
            stop,
            task: Some(tokio::spawn(accept(self, state, receiver))),
        }
    }
}

pub(crate) struct Running {
    address: SocketAddr,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl Running {
    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) fn stop(mut self) -> JoinHandle<()> {
        let _ = self.stop.send(true);
        self.task.take().expect("operator listener task is owned")
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

fn read_token(path: Option<&Path>) -> Result<Zeroizing<String>, Error> {
    let Some(path) = path.filter(|path| !path.as_os_str().is_empty()) else {
        return Ok(Zeroizing::new(String::new()));
    };
    let bytes = match std::fs::read(path) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            return Ok(Zeroizing::new(String::new()));
        }
        Err(error) => return Err(error.into()),
    };
    let source = std::str::from_utf8(&bytes)?;
    let mut token = Zeroizing::new(String::with_capacity(source.len()));
    let mut chars = source.chars().peekable();
    // Python's startup text-file read translates universal newlines before strip.
    while let Some(character) = chars.next() {
        if character == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            token.push('\n');
        } else {
            token.push(character);
        }
    }
    Ok(token)
}

async fn accept(prepared: Prepared, state: RuntimeState, mut stop: watch::Receiver<bool>) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            accepted = prepared.listener.accept() => match accepted {
                Ok((socket, peer)) => {
                    connections.spawn(serve_connection(
                        socket, peer, state.clone(), prepared.token.clone(), stop.clone(),
                    ));
                }
                Err(_) => {
                    eprintln!("Operator API listener failed");
                    if let Ok(runtime) = state.read() {
                        crate::clear_readiness(&runtime.config.readiness_file, &runtime.instance_id);
                    }
                    break;
                }
            },
            Some(_) = connections.join_next(), if !connections.is_empty() => {},
        }
    }
    drop(prepared.listener);
    if tokio::time::timeout(Duration::from_secs(10), async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
}

async fn serve_connection(
    socket: TcpStream,
    peer: SocketAddr,
    state: RuntimeState,
    token: Arc<Zeroizing<String>>,
    mut stop: watch::Receiver<bool>,
) {
    let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
        let state = state.clone();
        let token = token.clone();
        async move {
            let runtime = state
                .read()
                .map_err(|_| admin_api::Error::RegistryUnavailable)?
                .clone();
            let target = request.uri().to_string();
            // BaseHTTPRequestHandler collapses a leading // before dispatch.
            // Keep query and absolute-form presentation independently of routes.
            let path = if target.starts_with("//") {
                format!("/{}", target.trim_start_matches('/'))
            } else {
                target
            };
            let client_ip = request
                .headers()
                .get("x-forwarded-for")
                .filter(|value| !value.as_bytes().is_empty())
                .map(|value| {
                    // The source HTTP header parser decodes Latin-1. This is
                    // client-provided audit text, never trusted agent identity.
                    let value: String = value
                        .as_bytes()
                        .iter()
                        .map(|byte| char::from(*byte))
                        .collect();
                    value
                        .split(',')
                        .next()
                        .unwrap()
                        .trim_matches(python_whitespace)
                        .to_owned()
                })
                .unwrap_or_else(|| peer.ip().to_string());
            let stats = || {
                let logger = runtime
                    .request_logger
                    .stats()
                    .ok()
                    .and_then(|stats| stats.document().json().ok())
                    .unwrap_or_else(
                        || json!({"error":"RuntimeError: request logger stats unavailable"}),
                    );
                json!({"proxy":"safeyolo", "flow-recorder":runtime.flow_recorder.stats(),
                    "request-logger":logger})
            };
            let outcome = admin_api::respond_with_stats(
                request,
                token.trim_matches(python_whitespace),
                &runtime.tasks,
                runtime.policy.as_ref(),
                runtime.policy.as_ref().map(|_| &runtime.circuits),
                Some(&stats),
            )
            .await?
            .submit_audit(&runtime.audit, &client_ip, &path)?;
            let audits = outcome.audit().map(|intent| match intent {
                admin_api::Audit::AuthenticationFailed => vec![json!({
                    "event":"proxy.admin_api", "audit_intent":"admin.auth_failure",
                    "client_ip":client_ip, "path":path,
                    "reason":"invalid_or_missing_token",
                })],
                admin_api::Audit::TaskUpdated {
                    task_id,
                    permission_count,
                } => vec![json!({
                    "event":"proxy.admin_api", "audit_intent":"admin.task_policy_update",
                    "client_ip":client_ip, "task_id":task_id,
                    "permission_count":permission_count,
                })],
                admin_api::Audit::CircuitReset(reset) => reset.events(&client_ip).into(),
                admin_api::Audit::BudgetsReset(reset) => {
                    let safe_resource = reset.safe_resource();
                    let engine_resource = if reset.resets_all() {
                        serde_json::Value::String("all".into())
                    } else {
                        reset.resource().clone()
                    };
                    vec![
                        json!({"event":"proxy.admin_api", "audit_intent":"admin.budget_reset",
                            "kind":"admin", "severity":"medium", "addon":"policy-engine",
                            "summary":if reset.resets_all() { "All budgets reset".into() }
                                else { format!("Budget reset for {safe_resource}") },
                            "resource":engine_resource}),
                        json!({"event":"proxy.admin_api", "audit_intent":"admin.budgets_reset",
                            "kind":"admin", "severity":"medium", "addon":"admin-api",
                            "summary":format!("Budget counters reset: {safe_resource}"),
                            "client_ip":client_ip, "resource":reset.resource()}),
                    ]
                }
            });
            // Diagnostic sink failures remain separate from canonical producer
            // exceptions. Attempt each diagnostic without claiming rollback.
            let mut failed = false;
            for event in audits.into_iter().flatten() {
                failed |= runtime.record(event).is_err();
            }
            let mut response = outcome.into_response();
            if failed {
                eprintln!("Operator API evidence write failed");
                response
                    .headers_mut()
                    .insert("x-safeyolo-evidence-error", "true".parse().unwrap());
            }
            Ok::<_, admin_api::Error>(response)
        }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    // The shipped BaseHTTPRequestHandler closes after its HTTP/1.0 response.
    builder.keep_alive(false);
    let connection = builder.serve_connection(TokioIo::new(socket), service);
    tokio::pin!(connection);
    tokio::select! {
        _ = &mut connection => {},
        _ = stop.changed() => {
            connection.as_mut().graceful_shutdown();
            let _ = connection.await;
        }
    }
}
