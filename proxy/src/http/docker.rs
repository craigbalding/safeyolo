//! The Docker stream owner starts only after ordinary request admission.

use std::{fmt, sync::Arc, time::Instant};

use hyper::{Response, body::Incoming, header, upgrade::OnUpgrade};
use hyper_util::rt::TokioIo;
use serde_json::json;

use super::{Body, Destination, HttpTask, full, live_view, strip_hop_headers};
use crate::{ConnectionIdentity, Error, Runtime, UpgradeTasks};

/// Docker's API client decodes JSON failures from `message`, not `error`.
/// Only local, buffered refusals are adapted; daemon responses stay untouched.
pub(super) async fn client_error(reply: &mut Response<Body>) {
    use http_body_util::BodyExt;
    if !(reply.status().is_client_error() || reply.status().is_server_error())
        || reply.extensions().get::<live_view::Upstream>().is_some()
    {
        return;
    }
    let bytes = reply
        .body_mut()
        .collect()
        .await
        .expect("local replies have infallible buffered bodies")
        .to_bytes();
    let mut body = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .filter(serde_json::Value::is_object)
        .unwrap_or_else(|| json!({"error": String::from_utf8_lossy(&bytes)}));
    let message = body
        .get("message")
        .or_else(|| body.get("error"))
        .and_then(serde_json::Value::as_str)
        .filter(|message| !message.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("SafeYolo refused the Docker request: {}", reply.status()));
    body["message"] = json!(message);
    let bytes = bytes::Bytes::from(body.to_string());
    reply
        .headers_mut()
        .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    if reply.headers().contains_key(header::CONTENT_LENGTH) {
        reply
            .headers_mut()
            .insert(header::CONTENT_LENGTH, bytes.len().into());
    }
    if let Some(local) = reply
        .extensions_mut()
        .get_mut::<super::traffic::LocalResponse>()
    {
        local.size = bytes.len() as u64;
    }
    *reply.body_mut() = full(bytes);
}

/// These GETs obtain prerequisite facts for an already admitted operation.
/// They use the selected credential and the ordinary verified outbound route;
/// no client-selected URL, redirect, response payload or retry is exposed.
pub(super) async fn inspect(
    runtime: &Runtime,
    allowed: &super::AllowedRequest<'_>,
    provider: Option<&str>,
    access: &crate::services::docker::DockerAccess,
    inspection: &mut crate::services::docker::enforcement::Inspection,
    headers: &hyper::HeaderMap,
) -> Result<(), Error> {
    while let Some(resource) = inspection.next() {
        let path = resource.path()?;
        let observed = get(runtime, allowed, provider, headers, &path).await?;
        inspection.observe(access, &resource, observed)?;
        runtime.audit.emit(allowed.identity.request_event(
            "gateway.docker_inspected",
            crate::audit::Kind::Gateway,
            allowed.request_id,
            "Checked prerequisite Docker resource facts",
            json!({"path":path,"response_disclosed":false}),
        ))?;
    }
    Ok(())
}

/// Internal prerequisite GET. This never forwards a client-selected URL.
async fn read(
    runtime: &Runtime,
    allowed: &super::AllowedRequest<'_>,
    provider: Option<&str>,
    headers: &hyper::HeaderMap,
    path: &str,
) -> Result<(hyper::StatusCode, bytes::Bytes), Error> {
    use http_body_util::BodyExt;
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let outbound =
            super::open_outbound(runtime, allowed, provider, false, None, None, None).await?;
        let uri = if outbound.h1_request_form == super::H1RequestForm::Absolute {
            format!(
                "{}://{}{}",
                allowed.destination.scheme, allowed.destination.uri_authority, path
            )
        } else {
            path.to_owned()
        };
        let (mut sender, connection) = hyper::client::conn::http1::handshake::<
            _,
            http_body_util::Full<bytes::Bytes>,
        >(TokioIo::new(outbound.stream))
        .await?;
        let connection = super::HttpTask {
            task: allowed.tasks.spawn(async move {
                let _ = connection.await;
            }),
            completion: None,
            _session: None,
        };
        let mut request = hyper::Request::builder()
            .method("GET")
            .uri(uri)
            .header(hyper::header::HOST, &allowed.destination.authority)
            .header(hyper::header::CONNECTION, "close")
            .body(http_body_util::Full::new(bytes::Bytes::new()))?;
        // A custom auth header is permitted. Never forward client entity,
        // framing, upgrade or method-override fields into the inspection.
        if let Some(service) = runtime
            .policy
            .as_deref()
            .and_then(|p| p.gateway())
            .and_then(|g| {
                g.docker_for_endpoint(&allowed.destination.host, allowed.destination.port)
            })
            && let Some(auth) = &service.auth
            && let Some(value) = headers.get(&auth.header)
        {
            request.headers_mut().insert(
                hyper::header::HeaderName::try_from(&auth.header)?,
                value.clone(),
            );
        }
        let response = sender.send_request(request).await?;
        let status = response.status();
        let bytes = http_body_util::Limited::new(
            response.into_body(),
            crate::http_content::BUFFERED_BODY_THRESHOLD,
        )
        .collect()
        .await?
        .to_bytes();
        drop(connection);
        Ok::<_, Error>((status, bytes))
    })
    .await
    .map_err(|_| "Docker inspection timed out")?
}
async fn get(
    runtime: &Runtime,
    allowed: &super::AllowedRequest<'_>,
    provider: Option<&str>,
    headers: &hyper::HeaderMap,
    path: &str,
) -> Result<Option<serde_json::Value>, Error> {
    let (status, bytes) = read(runtime, allowed, provider, headers, path).await?;
    if status == hyper::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if status != hyper::StatusCode::OK {
        return Err("required Docker inspection failed".into());
    }
    Ok(Some(crate::contracts::strict_json(&bytes)?))
}

mod project;
pub(super) use project::ProjectRequest;

#[derive(Debug)]
pub(super) struct RouteError;
impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid Docker service selection")
    }
}
impl std::error::Error for RouteError {}

#[derive(Clone)]
pub(super) struct Operation {
    pub service: String,
    pub method: String,
    pub path: String,
}

impl Operation {
    pub(super) fn interrupted(
        &self,
        runtime: &Runtime,
        identity: &ConnectionIdentity,
        request_id: &str,
    ) {
        if !["GET", "HEAD"].contains(&self.method.as_str()) {
            let _ = runtime.audit.emit(identity.request_event(
                "gateway.docker_request", crate::audit::Kind::Gateway, request_id,
                "Docker response interrupted; mutation outcome is unknown. Inspect daemon state before retrying.",
                json!({"service":self.service,"method":self.method,"path":self.path,
                    "response_outcome":"interrupted","mutation_outcome":"unknown","replayed":false}),
            ));
        }
    }
}

struct StreamEvidence {
    runtime: Arc<Runtime>,
    identity: ConnectionIdentity,
    request_id: String,
    service: String,
    path: String,
    started: Instant,
    finished: bool,
}
impl StreamEvidence {
    fn finish(
        &mut self,
        outcome: &str,
        uploaded: Option<u64>,
        downloaded: Option<u64>,
        error: Option<&crate::tunnels::RelayError>,
    ) {
        self.finished = true;
        let _ = self.runtime.audit.emit(self.identity.request_event(
            "gateway.docker_stream.end", crate::audit::Kind::Gateway, &self.request_id,
            "Docker exec/attach stream ended. Inspect process state to determine the operation outcome.",
            json!({"service":self.service,"path":self.path,"stream_outcome":outcome,
                "uploaded_bytes":uploaded,"downloaded_bytes":downloaded,
                "duration_ms":self.started.elapsed().as_millis(),"operation_outcome":"unknown","replayed":false,
                "error":error}), // DOC: docs/docker.md
        ));
    }
}
impl Drop for StreamEvidence {
    fn drop(&mut self) {
        if !self.finished {
            self.finish("interrupted", None, None, None);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn upgrade(
    runtime: Arc<Runtime>,
    tasks: UpgradeTasks,
    identity: &ConnectionIdentity,
    request_id: &str,
    service: String,
    destination: &Destination,
    mut response: Response<Incoming>,
    client: OnUpgrade,
    connection: HttpTask,
    decision: String,
) -> Result<(Response<Body>, String), Error> {
    let valid = response.headers().get_all(header::UPGRADE).iter().count() == 1
        && response
            .headers()
            .get(header::UPGRADE)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"tcp"))
        && response
            .headers()
            .get_all(header::CONNECTION)
            .iter()
            .any(|value| {
                value
                    .as_bytes()
                    .split(|byte| *byte == b',')
                    .any(|part| part.trim_ascii().eq_ignore_ascii_case(b"upgrade"))
            });
    if !valid {
        Operation {
            service,
            method: "POST".into(),
            path: destination.path.split('?').next().unwrap_or("/").into(),
        }
        .interrupted(&runtime, identity, request_id);
        return Err(
            "invalid Docker exec/attach protocol switch; operation outcome is unknown".into(),
        );
    }
    let server = hyper::upgrade::on(&mut response);
    let (mut parts, _) = response.into_parts();
    parts.extensions.insert(live_view::Upstream);
    strip_hop_headers(&mut parts.headers);
    parts.headers.insert(header::CONNECTION, "Upgrade".parse()?);
    parts.headers.insert(header::UPGRADE, "tcp".parse()?);
    let mut evidence = StreamEvidence {
        runtime: runtime.clone(),
        identity: identity.clone(),
        request_id: request_id.into(),
        service,
        path: destination.path.split('?').next().unwrap_or("/").into(),
        started: Instant::now(),
        finished: false,
    };
    runtime.audit.emit(identity.request_event(
        "gateway.docker_stream.start",
        crate::audit::Kind::Gateway,
        request_id,
        "Admitted Docker exec/attach stream",
        json!({"service":evidence.service,"path":evidence.path}),
    ))?;
    let mut stop = tasks.stop.clone();
    tasks.spawn(async move {
        let _connection = connection;
        if *stop.borrow() {
            evidence.finish("shutdown", None, None, None);
            return;
        }
        let switched = tokio::select! {
            _ = stop.changed() => None,
            result = async { tokio::try_join!(client, server) } => Some(result),
        };
        match switched {
            Some(Ok((client, server))) => {
                let result = crate::tunnels::relay(
                    Box::new(TokioIo::new(client)),
                    Box::new(TokioIo::new(server)),
                    stop,
                )
                .await;
                evidence.finish(
                    result.outcome,
                    Some(result.uploaded),
                    Some(result.downloaded),
                    result.error.as_ref(),
                );
            }
            Some(Err(_)) => evidence.finish("upgrade_failed", None, None, None),
            None => evidence.finish("shutdown", None, None, None),
        }
    });
    Ok((
        Response::from_parts(parts, full(bytes::Bytes::new())),
        decision,
    ))
}
