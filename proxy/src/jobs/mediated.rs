//! Hyperlight callbacks use the existing delegated proxy, never a host dialer.
use super::{digest, network, now};
use crate::{Error, credentials::Secret};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

const MESSAGE_BYTES: usize = 48 * 1024;
const CHUNK_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceLimits {
    pub services: Vec<String>,
    pub max_calls: usize,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
}
impl ServiceLimits {
    pub(super) fn validate(&self) -> Result<(), Error> {
        if self.services.is_empty()
            || self.services.iter().any(String::is_empty)
            || self.max_calls == 0
            || self.max_request_bytes == 0
            || self.max_request_bytes > MESSAGE_BYTES
            || self.max_response_bytes == 0
            || self
                .max_calls
                .checked_mul(self.max_response_bytes)
                .is_none()
        {
            return Err("mediated_services needs named services, positive call/byte limits and max_request_bytes <= 49152".into());
        }
        Ok(())
    }
}

/// All identity, timing and transport fields are written by the host adapter.
#[derive(Clone, Debug, Serialize)]
pub struct ServiceEvidence {
    pub id: String,
    pub service: String,
    pub method: String,
    pub url: String,
    pub policy_hash: String,
    pub configuration_sha256: String,
    pub request_sha256: String,
    pub request_bytes: usize,
    pub request_body_base64: String,
    pub started_at_ms: u128,
    pub ended_at_ms: Option<u128>,
    pub request_started: bool,
    pub status: Option<u16>,
    pub blocked_by: Option<String>,
    pub response_bytes: Option<usize>,
    pub response_sha256: Option<String>,
    pub source_revision: Option<String>,
    pub response_date: Option<String>,
    pub last_modified: Option<String>,
    pub retained_base64: Option<String>,
    pub error: Option<String>,
    pub effect_outcome: String,
}

struct Capture {
    observation: ServiceEvidence,
    body: Vec<u8>,
}
#[derive(Clone, Default)]
pub(super) struct Captures(Arc<Mutex<Vec<Capture>>>);
impl Captures {
    pub(super) fn finish(&self) -> Result<Vec<ServiceEvidence>, Error> {
        let mut captures = self.0.lock().map_err(|_| "service evidence unavailable")?;
        for capture in captures.iter_mut() {
            if capture.observation.ended_at_ms.is_none() {
                capture.observation.ended_at_ms = Some(now()?);
                capture.observation.error =
                    Some("delegated call interrupted; late evidence discarded".into());
            }
        }
        Ok(captures
            .iter()
            .map(|capture| capture.observation.clone())
            .collect())
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Call {
    Service {
        service: String,
        method: String,
        url: String,
        #[serde(default)]
        body_base64: String,
    },
    Read {
        id: String,
        offset: usize,
        length: usize,
    },
}

pub(super) struct Bridge {
    listener: UnixListener,
    proxy: PathBuf,
    tokens: BTreeMap<String, Secret>,
    limits: ServiceLimits,
    policy_hash: String,
    configuration_sha256: String,
    captures: Captures,
}
impl Bridge {
    pub(super) fn new(
        listener: UnixListener,
        client: &network::Client,
        limits: ServiceLimits,
        captures: Captures,
    ) -> Result<Self, Error> {
        let (proxy, mut tokens) = client.service_access()?;
        tokens.retain(|name, _| limits.services.contains(name));
        Ok(Self {
            listener,
            proxy,
            tokens,
            limits,
            policy_hash: client.policy_hash.clone(),
            configuration_sha256: client.configuration_sha256.clone(),
            captures,
        })
    }

    /// One synchronous VM callback and one proxy request at a time. No detached
    /// call survives the owning invocation; the caller joins this task on exit.
    pub(super) async fn serve(self) -> Result<(), Error> {
        loop {
            let (mut stream, _) = self.listener.accept().await?;
            let result = async {
                let size = stream.read_u32().await? as usize;
                if size > self.limits.max_request_bytes || size > MESSAGE_BYTES {
                    return Err::<Value, Error>("host-call message limit exceeded".into());
                }
                let mut bytes = vec![0; size];
                stream.read_exact(&mut bytes).await?;
                match serde_json::from_slice::<Call>(&bytes)? {
                    Call::Read { id, offset, length } => self.read(&id, offset, length),
                    Call::Service {
                        service,
                        method,
                        url,
                        body_base64,
                    } => self.service(service, method, url, body_base64).await,
                }
            }
            .await;
            let reply = match result {
                Ok(value) => json!({"ok":true,"value":value}),
                Err(error) => json!({"ok":false,"error":error.to_string()}),
            };
            let bytes = serde_json::to_vec(&reply)?;
            if bytes.len() > MESSAGE_BYTES {
                return Err("host-call reply limit exceeded".into());
            }
            // A helper killed while waiting cannot leave a blocked writer.
            // The invocation's deadline/cancellation also bounds this future.
            if stream.write_u32(bytes.len().try_into()?).await.is_ok() {
                let _ = stream.write_all(&bytes).await;
            }
        }
    }

    fn read(&self, id: &str, offset: usize, length: usize) -> Result<Value, Error> {
        if length == 0 || length > CHUNK_BYTES {
            return Err("evidence read needs 1..16384 bytes".into());
        }
        let captures = self
            .captures
            .0
            .lock()
            .map_err(|_| "service evidence unavailable")?;
        let capture = captures
            .iter()
            .find(|capture| capture.observation.id == id)
            .ok_or("unknown evidence handle")?;
        if capture.observation.error.is_some() || capture.observation.ended_at_ms.is_none() {
            return Err("evidence is incomplete or unavailable".into());
        }
        let bytes = capture
            .body
            .get(offset..)
            .ok_or("evidence offset exceeds captured bytes")?;
        Ok(
            json!({"data_base64":STANDARD.encode(&bytes[..length.min(bytes.len())]),"total_bytes":capture.body.len()}),
        )
    }

    async fn service(
        &self,
        service: String,
        method: String,
        url: String,
        body_base64: String,
    ) -> Result<Value, Error> {
        let uri: hyper::Uri = url.parse()?;
        if !matches!(uri.scheme_str(), Some("http" | "https"))
            || uri.host().is_none()
            || uri
                .authority()
                .is_some_and(|authority| authority.as_str().contains('@'))
        {
            return Err("service call needs an HTTP(S) URL without user information".into());
        }
        let method: hyper::Method = method.parse()?;
        // CONNECT and protocol upgrade cannot tunnel an unmediated guest socket.
        if method == hyper::Method::CONNECT {
            return Err("guest tunnels are unavailable".into());
        }
        let token = self
            .tokens
            .get(&service)
            .ok_or("service is not selected or has no standing grant")?;
        let body = STANDARD.decode(body_base64)?;
        if body.len() > self.limits.max_request_bytes {
            return Err("service input limit exceeded".into());
        }
        let id = uuid::Uuid::new_v4().simple().to_string();
        let index = {
            let mut captures = self
                .captures
                .0
                .lock()
                .map_err(|_| "service evidence unavailable")?;
            if captures.len() >= self.limits.max_calls {
                return Err("service call limit exceeded".into());
            }
            let index = captures.len();
            captures.push(Capture {
                observation: ServiceEvidence {
                    id: id.clone(),
                    service,
                    method: method.to_string(),
                    url,
                    policy_hash: self.policy_hash.clone(),
                    configuration_sha256: self.configuration_sha256.clone(),
                    request_sha256: digest(&body),
                    request_bytes: body.len(),
                    request_body_base64: STANDARD.encode(&body),
                    started_at_ms: now()?,
                    ended_at_ms: None,
                    request_started: false,
                    status: None,
                    blocked_by: None,
                    response_bytes: None,
                    response_sha256: None,
                    source_revision: None,
                    response_date: None,
                    last_modified: None,
                    retained_base64: None,
                    error: None,
                    effect_outcome: if matches!(
                        method,
                        hyper::Method::GET | hyper::Method::HEAD | hyper::Method::OPTIONS
                    ) {
                        "read_only"
                    } else {
                        "not_started"
                    }
                    .into(),
                },
                body: Vec::new(),
            });
            index
        };
        let work = async {
            let stream = UnixStream::connect(&self.proxy).await?;
            let (mut client, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
            let _driver = Connection(tokio::spawn(connection));
            let request = hyper::Request::builder()
                .method(method.clone())
                .uri(uri.clone())
                .header("host", uri.authority().unwrap().as_str())
                .header("authorization", format!("Bearer {}", token.expose_secret()))
                .header("user-agent", "SafeYolo-mediated-job")
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(body)))?;
            self.update(index, |record| {
                record.request_started = true;
                if record.effect_outcome != "read_only" {
                    record.effect_outcome = "uncertain".into();
                }
            })?;
            let response = client.send_request(request).await?;
            let status = response.status();
            let header = |name| {
                response
                    .headers()
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned)
            };
            self.update(index, |record| {
                record.status = Some(status.as_u16());
                record.blocked_by = header("x-blocked-by");
                record.source_revision = header("etag");
                record.response_date = header("date");
                record.last_modified = header("last-modified");
            })?;
            let mut body = response.into_body();
            let mut bytes = Vec::new();
            while let Some(frame) = body.frame().await {
                if let Ok(data) = frame?.into_data() {
                    if data.len() > self.limits.max_response_bytes.saturating_sub(bytes.len()) {
                        return Err::<_, Error>(
                            "service response limit exceeded; evidence not retained".into(),
                        );
                    }
                    bytes.extend_from_slice(&data);
                }
            }
            let mut captures = self
                .captures
                .0
                .lock()
                .map_err(|_| "service evidence unavailable")?;
            let capture = &mut captures[index];
            let record = &mut capture.observation;
            record.response_bytes = Some(bytes.len());
            record.response_sha256 = Some(digest(&bytes));
            record.retained_base64 = Some(STANDARD.encode(&bytes));
            if record.effect_outcome != "read_only" {
                record.effect_outcome = "response_observed".into();
            }
            capture.body = bytes;
            if !status.is_success() {
                return Err(format!(
                    "{}: HTTP {status}",
                    if record.blocked_by.is_some() {
                        "policy_denied"
                    } else {
                        "provider_failure"
                    }
                )
                .into());
            }
            Ok::<_, Error>(())
        }
        .await;
        self.update(index, |record| {
            record.ended_at_ms = Some(crate::policy::current_time_ms() as u128);
            record.error = work.as_ref().err().map(ToString::to_string);
        })?;
        work?;
        let captures = self
            .captures
            .0
            .lock()
            .map_err(|_| "service evidence unavailable")?;
        let record = &captures[index].observation;
        // The callback gets a small handle; evidence bytes use bounded reads.
        Ok(
            json!({"id":id,"status":record.status,"bytes":record.response_bytes,"sha256":record.response_sha256}),
        )
    }

    fn update(&self, index: usize, change: impl FnOnce(&mut ServiceEvidence)) -> Result<(), Error> {
        let mut captures = self
            .captures
            .0
            .lock()
            .map_err(|_| "service evidence unavailable")?;
        change(&mut captures[index].observation);
        Ok(())
    }
}

struct Connection(tokio::task::JoinHandle<hyper::Result<()>>);
impl Drop for Connection {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests;
