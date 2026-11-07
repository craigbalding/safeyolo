//! The Docker stream owner starts only after ordinary request admission.

use std::{fmt, sync::Arc, time::Instant};

use hyper::{Response, body::Incoming, header, upgrade::OnUpgrade};
use hyper_util::rt::TokioIo;
use serde_json::json;

use super::{Body, Destination, HttpTask, full, live_view, strip_hop_headers};
use crate::{ConnectionIdentity, Error, Runtime, UpgradeTasks};

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
    fn finish(&mut self, outcome: &str, uploaded: Option<u64>, downloaded: Option<u64>) {
        self.finished = true;
        let _ = self.runtime.audit.emit(self.identity.request_event(
            "gateway.docker_stream.end", crate::audit::Kind::Gateway, &self.request_id,
            "Docker exec/attach stream ended. Inspect process state to determine the operation outcome.",
            json!({"service":self.service,"path":self.path,"stream_outcome":outcome,
                "uploaded_bytes":uploaded,"downloaded_bytes":downloaded,
                "duration_ms":self.started.elapsed().as_millis(),"operation_outcome":"unknown","replayed":false}),
        ));
    }
}
impl Drop for StreamEvidence {
    fn drop(&mut self) {
        if !self.finished {
            self.finish("interrupted", None, None);
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
            evidence.finish("shutdown", None, None);
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
                );
            }
            Some(Err(_)) => evidence.finish("upgrade_failed", None, None),
            None => evidence.finish("shutdown", None, None),
        }
    });
    Ok((
        Response::from_parts(parts, full(bytes::Bytes::new())),
        decision,
    ))
}
