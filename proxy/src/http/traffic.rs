//! Reached HTTP traffic hooks and stable, content-free per-exchange facts.
//! Body ownership and validated completion remain with the existing HTTP driver.

use std::sync::{Arc, Mutex, OnceLock};

use hyper::{Request, header};
use zeroize::Zeroizing;

use crate::{
    ConnectionIdentity, RuntimeState,
    circuits::CircuitValue,
    http_content::{self, ContentError},
    request_logger::{self as logger, Error, ErrorKind},
};

struct HookState {
    exchange: logger::Exchange,
    metrics_start: Option<f64>,
    started: Option<f64>,
    requested: bool,
    responded: bool,
}

pub(super) struct Traffic {
    state: RuntimeState,
    hooks: Mutex<HookState>,
    pub(super) method: String,
    pub(super) host: String,
    parsed: Result<super::traffic_url::PrettyUrl, Error>,
    request_parsed: OnceLock<Result<super::traffic_url::PrettyUrl, Error>>,
    request_id: String,
    agent: Zeroizing<String>,
    client: Option<Zeroizing<String>>,
}

impl Traffic {
    pub(super) fn new<B>(
        state: RuntimeState,
        identity: &ConnectionIdentity,
        request_id: &str,
        request: &Request<B>,
        destination: &super::Destination,
    ) -> Arc<Self> {
        let parsed = project(request, destination);
        Arc::new(Self {
            state,
            hooks: Mutex::new(HookState {
                exchange: logger::Exchange::new(
                    identity.audit_attribution(),
                    Some(identity.agent_id.clone()),
                ),
                metrics_start: None,
                started: None,
                requested: false,
                responded: false,
            }),
            method: request.method().to_string(),
            host: destination.policy_host.clone(),
            parsed,
            request_parsed: OnceLock::new(),
            request_id: request_id.to_owned(),
            agent: Zeroizing::new(identity.agent_id.clone()),
            client: identity.source_id.clone().map(Zeroizing::new),
        })
    }

    pub(super) fn request_headers<B>(
        &self,
        request: &Request<B>,
        destination: &super::Destination,
    ) {
        let _ = self.request_parsed.set(project(request, destination));
    }

    /// RequestId runs before later request consumers, including a failing one.
    pub(super) fn begin_request(&self) -> f64 {
        let mut hooks = self.hooks.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(started) = hooks.started {
            return started;
        }
        let started = crate::circuit_runtime::now();
        hooks.started = Some(started);
        if let Ok(runtime) = self.state.read() {
            runtime.observe_agent(&self.agent, self.client.as_deref().map(String::as_str));
        }
        started
    }

    pub(super) fn source_metadata_reached(&self) -> bool {
        self.hooks
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .started
            .is_some()
    }

    fn request_facts(&self, started: Option<f64>) -> logger::Request<'_> {
        let parsed = if started.is_some() {
            self.request_parsed.get().unwrap_or(&self.parsed)
        } else {
            &self.parsed
        };
        logger::Request {
            method: &self.method,
            parsed: parsed
                .as_ref()
                .map(|parsed| logger::PrettyUrl {
                    host: &parsed.host,
                    path: &parsed.path,
                })
                .map_err(|error| *error),
            request_id: started.map(|_| self.request_id.as_str()),
            client: self.client.as_deref().map(String::as_str),
        }
    }

    pub(super) fn request(&self, decoded_size: impl FnOnce() -> Result<u64, Error>) -> bool {
        let mut hooks = self.hooks.lock().unwrap_or_else(|error| error.into_inner());
        if hooks.requested {
            return false;
        }
        hooks.requested = true;
        let runtime = match self.state.read() {
            Ok(runtime) => runtime.clone(),
            Err(_) => return report(Err(Error(ErrorKind::Poisoned))),
        };
        let facts = self.request_facts(hooks.started);
        let logged = runtime.request_logger.request(
            runtime.policy.as_ref(),
            &mut hooks.exchange,
            &facts,
            decoded_size,
            &runtime.audit,
        );
        if let Err(error) = logged {
            return report(Err(error));
        }
        match runtime
            .metrics
            .request(&self.host, crate::circuit_runtime::now)
        {
            Ok(started) => {
                hooks.metrics_start = Some(started);
                false
            }
            Err(error) => report_metrics(error),
        }
    }

    pub(super) fn response(
        &self,
        status: u16,
        blocked_by: Option<&CircuitValue>,
        block_reason: Option<&CircuitValue>,
        decoded_size: impl FnOnce() -> Result<u64, Error>,
    ) -> bool {
        let mut hooks = self.hooks.lock().unwrap_or_else(|error| error.into_inner());
        if hooks.responded {
            return false;
        }
        hooks.responded = true;
        let runtime = match self.state.read() {
            Ok(runtime) => runtime.clone(),
            Err(_) => return report(Err(Error(ErrorKind::Poisoned))),
        };
        let logged = runtime.request_logger.response(
            &hooks.exchange,
            &self.request_facts(hooks.started),
            &logger::Response {
                status: Some(status),
                start_time: hooks.started,
                now: crate::circuit_runtime::now(),
                blocked_by,
                block_reason,
                credential_fingerprint: None,
                attribution_quarantined: false,
            },
            decoded_size,
            &runtime.audit,
        );
        if let Err(error) = logged {
            return report(Err(error));
        }
        match runtime.metrics.response(
            &self.host,
            hooks.metrics_start,
            blocked_by,
            Some(status),
            crate::circuit_runtime::now,
        ) {
            Ok(()) => false,
            Err(error) => report_metrics(error),
        }
    }
}

fn project<B>(
    request: &Request<B>,
    destination: &super::Destination,
) -> Result<super::traffic_url::PrettyUrl, Error> {
    (|| {
        let host = super::test_context::combined(request.headers(), header::HOST)
            .map_err(|_| Error(ErrorKind::Compatibility))?;
        let host = std::str::from_utf8(&host).map_err(|_| Error(ErrorKind::Compatibility))?;
        super::traffic_url::project(super::traffic_url::Input {
            scheme: &destination.scheme,
            host: &destination.policy_host,
            port: destination.port,
            path: &destination.path,
            host_header: request.headers().contains_key(header::HOST).then_some(host),
            authority: request.uri().authority().map(|value| value.as_str()),
            http2: request.version() == hyper::Version::HTTP_2,
        })
        .map_err(|error| {
            Error(match error {
                super::traffic_url::Error::Parse => ErrorKind::Value,
                super::traffic_url::Error::Compatibility => ErrorKind::Compatibility,
            })
        })
    })()
}

pub(super) fn decoded_size(
    content: Option<&[u8]>,
    encoding: Result<&[u8], ContentError>,
) -> Result<u64, Error> {
    let Some(content) = content else {
        return Ok(0);
    };
    http_content::decode_prefix_with_size(
        content,
        encoding.map_err(|_| Error(ErrorKind::Decode))?,
        0,
    )
    .map(|decoded| decoded.total_bytes as u64)
    .map_err(|_| Error(ErrorKind::Decode))
}

fn report(result: Result<(), Error>) -> bool {
    if let Err(error) = result {
        eprintln!("Request logger hook failed: {:?}", error.0);
        matches!(error.0, ErrorKind::Audit | ErrorKind::Poisoned)
    } else {
        false
    }
}

fn report_metrics(error: crate::metrics::Error) -> bool {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr().lock(), "Metrics hook failed: {error}");
    matches!(error.kind(), crate::metrics::ErrorKind::Poisoned)
}

#[cfg(test)]
fn metrics_stats(runtime: &crate::Runtime) -> serde_json::Value {
    runtime.metrics.get_stats().unwrap().json().unwrap()
}

/// A local API response whose existing request reader crossed parser EOM.
/// Trusted outcome metadata is carried directly, never inferred from headers.
#[derive(Clone)]
pub(super) struct LocalResponse {
    pub(super) traffic: Arc<Traffic>,
    pub(super) size: u64,
    pub(super) blocked_by: Option<CircuitValue>,
    pub(super) block_reason: Option<CircuitValue>,
}
impl LocalResponse {
    pub(super) fn finish(self, status: u16) -> bool {
        self.traffic.response(
            status,
            self.blocked_by.as_ref(),
            self.block_reason.as_ref(),
            || Ok(self.size),
        )
    }
}

/// A head-selected local reply may have a genuinely completed empty request.
/// Do not poll/drain body frames or wait for a missing terminal to create logs.
pub(super) fn local_reply<B: hyper::body::Body>(
    traffic: Option<&Arc<Traffic>>,
    request: &mut Request<B>,
    reply: &mut hyper::Response<super::Body>,
    blocked_by: Option<serde_json::Value>,
    block_reason: Option<serde_json::Value>,
    destination: &super::Destination,
    hygiene_applied: bool,
) -> Result<(), crate::Error> {
    use hyper::body::Body as _;
    let Some(traffic) = traffic.filter(|_| request.body().is_end_stream()) else {
        return Ok(());
    };
    let Some(size) = reply.body().size_hint().exact() else {
        return Ok(());
    };
    if !matches!(
        super::request_context::Observer::take(request)?.try_result(),
        Some(Ok(()))
    ) {
        return Ok(());
    }
    if !hygiene_applied {
        let mut headers = crate::request_headers::RequestHeaders::take(request)?;
        headers.apply_hygiene(request.headers_mut());
    }
    traffic.request_headers(request, destination);
    let encoding = super::test_context::combined(request.headers(), header::CONTENT_ENCODING);
    traffic.begin_request();
    let failed = traffic.request(|| {
        decoded_size(
            Some(&[]),
            encoding
                .as_deref()
                .map(Vec::as_slice)
                .map_err(|error| *error),
        )
    });
    reply.extensions_mut().insert(LocalResponse {
        traffic: traffic.clone(),
        size,
        blocked_by: blocked_by.map(Into::into),
        block_reason: block_reason.map(Into::into),
    });
    if failed {
        reply
            .headers_mut()
            .insert("x-safeyolo-evidence-error", "true".parse()?);
    }
    Ok(())
}

#[cfg(test)]
mod local_tests;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod upgrade_stats_tests;
