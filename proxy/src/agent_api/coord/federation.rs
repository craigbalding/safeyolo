//! Separate TLS boundary for explicitly authorized remote Coord participation.
//! The peer SafeYolo authenticates its own agent listener. The home authenticates
//! that SafeYolo, qualifies the principal, and runs the ordinary local kernel.
use super::*;
use crate::{Error, coord_rooms::federation as trust};
use http_body_util::{Full, Limited};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde::Deserialize;
use std::{convert::Infallible, io::Write, sync::Arc};

const MAX_WIRE_REQUEST: usize = MAX_COORD_REQUEST_BYTES + 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerRequest {
    agent_id: String,
    method: String,
    path: String,
    body: Option<Value>,
}

pub(crate) fn pinned_tls(ca: &Path) -> Result<Arc<rustls::ClientConfig>, Error> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_reader_iter(std::fs::File::open(ca)?) {
        roots.add(cert?)?;
    }
    if roots.is_empty() {
        return Err("home TLS trust file contains no certificates".into());
    }
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(tls))
}

impl CoordClient {
    pub(super) async fn check_remote(&self) -> Result<(), CoordError> {
        let Some(remote) = self.remote.clone() else {
            return Ok(());
        };
        let db = self.owner.data_dir.join("v0.db");
        tokio::task::spawn_blocking(move || {
            trust::authorize(&open_db(&db, false)?, &remote).map_err(|_| CoordError::Forbidden)
        })
        .await
        .map_err(|_| CoordError::Unavailable)?
    }
}

fn without_home(path: &str) -> Result<String, CoordError> {
    let Some((path, query)) = path.split_once('?') else {
        return Err(CoordError::Invalid);
    };
    let mut home_count = 0;
    let mut retained = Vec::new();
    for part in query.split('&') {
        let key =
            percent_encoding::percent_decode_str(part.split_once('=').map_or(part, |(key, _)| key))
                .decode_utf8()
                .map_err(|_| CoordError::Invalid)?;
        if key == "home" {
            home_count += 1;
        } else {
            retained.push(part);
        }
    }
    if home_count != 1 {
        return Err(CoordError::Invalid);
    }
    Ok(if retained.is_empty() {
        path.into()
    } else {
        format!("{path}?{}", retained.join("&"))
    })
}

pub(super) async fn forward(
    request: Request<'_>,
    context: &CoordContext<'_>,
    payload: Option<&[u8]>,
    agent_name: &str,
    principal: &str,
    home_name: &str,
) -> Outcome<'static> {
    if !public_name_part(home_name) {
        return error_response(CoordError::Invalid);
    }
    let path = match without_home(request.path_and_query) {
        Ok(path) => path,
        Err(error) => return error_response(error),
    };
    if !allowed(Request {
        path_and_query: &path,
        ..request
    }) {
        return error_response(CoordError::NotFound);
    }
    let db = context.client.owner.data_dir.join("v0.db");
    let name = home_name.to_owned();
    let read_db = db.clone();
    let home = match tokio::task::spawn_blocking(move || {
        trust::home(
            &open_db(&read_db, false).map_err(|_| "Coord store unavailable")?,
            &name,
        )
    })
    .await
    {
        Ok(Ok(home)) => home,
        _ => {
            return response(
                403,
                json!({"error":"home is not authorized on this instance"}),
            );
        }
    };
    let body = match payload
        .filter(|_| request.method == "POST")
        .map(serde_json::from_slice::<Value>)
        .transpose()
    {
        Ok(body) => body,
        Err(_) => return response(400, json!({"error":"invalid JSON body"})),
    };
    let acquired = async {
        let credential = trust::token(&home.token_file)?;
        let tls = pinned_tls(&home.ca_file)?;
        crate::native_client::federation_json(
            &format!("{}/coord", home.url),
            credential.trim(),
            json!({"agent_id":principal,"method":request.method,"path":path,"body":body}),
            tls,
        )
        .await
    };
    let mut cancellation = context.cancellation.clone();
    let result = tokio::select! {
        result = acquired => result,
        _ = wait_cancelled(&mut cancellation) => return error_response(CoordError::Cancelled),
    };
    // Route revocation and local identity replacement also apply to responses
    // already in flight. A home reference is never an agent capability.
    let name = home_name.to_owned();
    let expected = home.clone();
    let still_authorized = tokio::task::spawn_blocking(move || {
        trust::home(
            &open_db(&db, false).map_err(|_| "Coord store unavailable")?,
            &name,
        )
        .map(|current| current == expected)
    })
    .await;
    if !matches!(still_authorized, Ok(Ok(true)))
        || context
            .client
            .principal_id(agent_name)
            .await
            .ok()
            .as_deref()
            != Some(principal)
    {
        return error_response(CoordError::Forbidden);
    }
    match result {
        Ok(reply) if reply["home_instance_id"] == home.instance_id => {
            let Some(status) = reply["status"]
                .as_u64()
                .and_then(|s| u16::try_from(s).ok())
                .filter(|s| (200..600).contains(s))
            else {
                return error_response(CoordError::Data);
            };
            match reply.get("body") {
                Some(body) => response(status, body.clone()),
                None => error_response(CoordError::Data),
            }
        }
        Ok(_) => response(
            503,
            json!({"error":"home identity does not match the configured instance"}),
        ),
        Err(error)
            if error
                .downcast_ref::<crate::native_client::RestStatusError>()
                .is_some_and(|error| error.status == 403) =>
        {
            response(
                403,
                json!({"error":"home federation access denied; reconcile any in-flight mutation before retrying"}),
            )
        }
        Err(_) => response(
            503,
            json!({"error":"home unavailable; a mutation may have committed. Reconcile with the home; retry durable mutations only with their original operation ID and inputs. Inspect history before repeating a send.",
            "mutation_outcome":if request.method=="POST" { "unknown" } else { "not_requested" },
            "send_outcome":if route_parts(request).is_some_and(|(_,op)|op=="send") { json!("unknown") } else {Value::Null}}),
        ),
    }
}

fn allowed(request: Request<'_>) -> bool {
    request.path_and_query.len() <= 16384
        && query_parameter(request.path_and_query, "home").is_ok_and(|home| home.is_none())
        && (route_parts(request).is_some()
            || attention_wait_route(request)
            || attention_object_route(request).is_some())
}

fn wire(status: u16, value: Value) -> hyper::Response<Full<Bytes>> {
    hyper::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("connection", "close")
        .body(Full::new(Bytes::from(value.to_string())))
        .expect("fixed federation response headers")
}

async fn receive(
    client: Arc<CoordClient>,
    request: hyper::Request<Incoming>,
    cancellation: tokio::sync::watch::Receiver<bool>,
    instance_id: Arc<String>,
) -> hyper::Response<Full<Bytes>> {
    if request.method() != hyper::Method::POST
        || request.uri().path_and_query().map(|p| p.as_str()) != Some("/coord")
    {
        return wire(404, json!({"error":"federation endpoint not found"}));
    }
    let auth = request
        .headers()
        .get_all(hyper::header::AUTHORIZATION)
        .iter()
        .collect::<Vec<_>>();
    if auth.len() != 1 {
        return wire(403, json!({"error":"peer authentication required"}));
    }
    let Some(credential) = auth[0]
        .as_bytes()
        .strip_prefix(b"Bearer ")
        .map(|b| zeroize::Zeroizing::new(b.to_vec()))
    else {
        return wire(403, json!({"error":"peer authentication required"}));
    };
    let payload = tokio::time::timeout(
        Duration::from_secs(10),
        Limited::new(request.into_body(), MAX_WIRE_REQUEST).collect(),
    )
    .await;
    let bytes = match payload {
        Ok(Ok(body)) => body.to_bytes(),
        _ => {
            return wire(
                413,
                json!({"error":"invalid or oversized federation request"}),
            );
        }
    };
    let Ok(peer) = serde_json::from_slice::<PeerRequest>(&bytes) else {
        return wire(400, json!({"error":"invalid federation request"}));
    };
    let db = client.owner.data_dir.join("v0.db");
    let agent = peer.agent_id;
    let remote = match tokio::task::spawn_blocking(move || {
        trust::authenticate(
            &open_db(&db, false).map_err(|_| "Coord store unavailable")?,
            &credential,
            &agent,
        )
    })
    .await
    {
        Ok(Ok(remote)) => remote,
        _ => {
            return wire(
                403,
                json!({"error":"peer or remote agent is not authorized"}),
            );
        }
    };
    let request = Request {
        method: &peer.method,
        path_and_query: &peer.path,
        authorization: None,
        identity: crate::network_guard::Identity::Resolved(&remote.display_name),
        client_ip: None,
        request_id: "federation",
    };
    if !allowed(request) {
        return wire(404, json!({"error":"remote operation is not available"}));
    }
    let payload = peer
        .body
        .map(|body| serde_json::to_vec(&body))
        .transpose()
        .expect("JSON value serialization");
    let max = match route_parts(request).map(|(_, op)| op) {
        Some("send") => MAX_COORD_REQUEST_BYTES,
        Some("work") => crate::coord_rooms::work::MAX_REQUEST_BYTES,
        Some("signals") => crate::coord_rooms::signals::MAX_REQUEST_BYTES,
        _ => MAX_DECLARATION_REQUEST_BYTES,
    };
    if payload.as_ref().is_some_and(|bytes| bytes.len() > max) {
        return wire(413, json!({"error":"request body too large"}));
    }
    let scoped = CoordClient {
        owner: client.owner.clone(),
        policy_file: client.policy_file.clone(),
        provider_directory: client.provider_directory.clone(),
        remote: Some(remote.clone()),
        relay_config: client.relay_config.clone(),
    };
    let outcome = respond_as(
        request,
        CoordContext {
            client: &scoped,
            cancellation,
            runtime: None,
        },
        payload.as_deref(),
        &remote.principal_id,
        &remote.display_name,
    )
    .await;
    if scoped.check_remote().await.is_err() {
        return wire(403, json!({"error":"federation access changed"}));
    }
    let super::super::ResponseBody::Json(body) = &outcome.response.body else {
        return wire(503, json!({"error":"Coord response unavailable"}));
    };
    wire(
        200,
        json!({"home_instance_id":*instance_id,"status":outcome.response.status,"body":body}),
    )
}

struct Cancel(tokio::sync::watch::Sender<bool>);
impl Drop for Cancel {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}

/// A foreground, operator-owned listener. It exposes only the whitelisted
/// Coord operations and never the Agent/Admin API, NATS or local credentials.
pub(crate) async fn serve(
    root: &Path,
    listen: &str,
    cert: &Path,
    key: &Path,
) -> Result<Value, Error> {
    crate::coord_rooms::bootstrap(root)?;
    let config = crate::native_config::read(&root.join("config.toml"))?;
    let certificates = CertificateDer::pem_reader_iter(std::fs::File::open(cert)?)
        .collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(&zeroize::Zeroizing::new(std::fs::read(key)?))?;
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(certificates, key)?;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let mut client = CoordClient::new(
        config.policy_file,
        config.data_dir.map(|dir| dir.join("coord")),
    );
    client.relay_config = Some(root.join("config.toml"));
    let client = Arc::new(client);
    let instance_id = Arc::new(
        std::fs::read_to_string(client.owner.data_dir.join("instance_id"))?
            .trim()
            .to_owned(),
    );
    let listener = tokio::net::TcpListener::bind(listen).await?;
    println!(
        "{}",
        json!({"federation_listen":listener.local_addr()?.to_string(),"home_instance_id":*instance_id})
    );
    std::io::stdout().flush()?;
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            result=listener.accept() => {
                let (socket,_)=result?;
                let acceptor=acceptor.clone();
                let client=client.clone();
                let instance_id=instance_id.clone();
                connections.spawn(async move {
                    let Ok(Ok(socket))=tokio::time::timeout(Duration::from_secs(5),acceptor.accept(socket)).await else { return; };
                    let (cancel,receiver)=tokio::sync::watch::channel(false);
                    let _cancel=Cancel(cancel);
                    let connection=hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket),service_fn(move |request| {
                        let (client,receiver,instance_id)=(client.clone(),receiver.clone(),instance_id.clone());
                        async move { Ok::<_,Infallible>(receive(client,request,receiver,instance_id).await) }
                    }));
                    let _=tokio::time::timeout(Duration::from_secs(350),connection).await;
                });
            }
            _=connections.join_next(), if !connections.is_empty() => {}
            result=tokio::signal::ctrl_c() => { result?; break; }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    client.shutdown().await;
    Ok(json!({"stopped":true}))
}

#[cfg(test)]
mod tests;
