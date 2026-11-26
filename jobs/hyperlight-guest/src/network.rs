//! The Core guest owns HTTP parsing, TLS and certificate validation.
//! The callback supplies only the selected proxy stream, clock and entropy.

use alloc::{
    collections::VecDeque,
    format,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use core::{
    fmt,
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
    time::Duration,
};
use embedded_io::{ErrorKind, ErrorType};
use embedded_io_async::{Read, Write};
use nourl::{Url, UrlScheme};
use reqwless::{
    client::HttpConnection,
    request::{Request, RequestBuilder},
    response::Response,
};
use rustls::{
    ClientConfig, RootCertStore,
    client::UnbufferedClientConnection,
    pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject},
    time_provider::TimeProvider,
    unbuffered::ConnectionState,
};
use serde_json::{Value, json};

const CHUNK: usize = 16 * 1024;
const TLS_BUFFER: usize = 64 * 1024;

#[derive(Debug)]
pub struct Error(String);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl core::error::Error for Error {}
impl embedded_io::Error for Error {
    fn kind(&self) -> ErrorKind {
        ErrorKind::Other
    }
}
fn error(value: impl fmt::Debug) -> Error {
    Error(format!("{value:?}"))
}

struct ProxyStream<'a, F: FnMut(Value) -> Result<Value, String>> {
    id: u64,
    call: &'a mut F,
}
impl<F: FnMut(Value) -> Result<Value, String>> ErrorType for ProxyStream<'_, F> {
    type Error = Error;
}
impl<F: FnMut(Value) -> Result<Value, String>> Read for ProxyStream<'_, F> {
    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Error> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let length = buffer.len().min(CHUNK);
        let reply = (self.call)(json!({"kind":"proxy_read","id":self.id,"length":length}))
            .map_err(error)?;
        let bytes = STANDARD
            .decode(
                reply["data_base64"]
                    .as_str()
                    .ok_or_else(|| error("missing bytes"))?,
            )
            .map_err(error)?;
        if bytes.len() > length {
            return Err(error("proxy read exceeds its limit"));
        }
        buffer[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }
}
impl<F: FnMut(Value) -> Result<Value, String>> Write for ProxyStream<'_, F> {
    async fn write(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let bytes = &bytes[..bytes.len().min(CHUNK)];
        let reply = (self.call)(
            json!({"kind":"proxy_write","id":self.id,"data_base64":STANDARD.encode(bytes)}),
        )
        .map_err(error)?;
        let count = reply["written"]
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .filter(|n| *n > 0 && *n <= bytes.len())
            .ok_or_else(|| error("invalid proxy write count"))?;
        Ok(count)
    }
    async fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
impl<F: FnMut(Value) -> Result<Value, String>> Drop for ProxyStream<'_, F> {
    fn drop(&mut self) {
        // Teardown also closes the host's complete invocation-owned stream table.
        let _ = (self.call)(json!({"kind":"proxy_close","id":self.id}));
    }
}

#[derive(Debug)]
struct Clock(fn() -> Option<u64>);
impl TimeProvider for Clock {
    fn current_time(&self) -> Option<UnixTime> {
        (self.0)().map(|seconds| UnixTime::since_unix_epoch(Duration::from_secs(seconds)))
    }
}

struct TlsStream<S> {
    stream: S,
    tls: UnbufferedClientConnection,
    incoming: Vec<u8>,
    outgoing: Vec<u8>,
    plaintext: VecDeque<u8>,
    closed: bool,
}
impl<S: Read<Error = Error> + Write<Error = Error>> TlsStream<S> {
    fn new(stream: S, config: ClientConfig, host: &str) -> Result<Self, Error> {
        Ok(Self {
            stream,
            tls: UnbufferedClientConnection::new(
                Arc::new(config),
                ServerName::try_from(host.to_string()).map_err(error)?,
            )
            .map_err(error)?,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            plaintext: VecDeque::new(),
            closed: false,
        })
    }

    async fn drive(&mut self, input: Option<&[u8]>) -> Result<Option<usize>, Error> {
        loop {
            let status = self.tls.process_tls_records(&mut self.incoming);
            let mut discard = status.discard;
            let mut read_more = false;
            let mut written = None;
            match status.state.map_err(error)? {
                ConnectionState::EncodeTlsData(mut state) => {
                    let mut bytes = vec![0; TLS_BUFFER];
                    let count = state.encode(&mut bytes).map_err(error)?;
                    if self.outgoing.len() + count > TLS_BUFFER {
                        return Err(error("TLS output buffer exceeded"));
                    }
                    self.outgoing.extend_from_slice(&bytes[..count]);
                }
                ConnectionState::TransmitTlsData(state) => {
                    self.stream.write_all(&self.outgoing).await.map_err(error)?;
                    self.outgoing.clear();
                    state.done();
                }
                ConnectionState::ReadTraffic(mut state) => {
                    while let Some(record) = state.next_record() {
                        let record = record.map_err(error)?;
                        discard += record.discard;
                        self.plaintext.extend(record.payload);
                    }
                }
                ConnectionState::WriteTraffic(mut state) => {
                    if let Some(input) = input {
                        let input = &input[..input.len().min(CHUNK)];
                        let mut bytes = vec![0; CHUNK + 1024];
                        let count = state.encrypt(input, &mut bytes).map_err(error)?;
                        self.stream
                            .write_all(&bytes[..count])
                            .await
                            .map_err(error)?;
                        written = Some(input.len());
                    } else {
                        read_more = true;
                    }
                }
                ConnectionState::BlockedHandshake => read_more = true,
                ConnectionState::Closed | ConnectionState::PeerClosed => self.closed = true,
                _ => return Err(error("unsupported TLS connection state")),
            }
            self.incoming.drain(..discard);
            if written.is_some() {
                return Ok(written);
            }
            if !self.plaintext.is_empty() && input.is_none() {
                return Ok(None);
            }
            if self.closed {
                return if input.is_some() {
                    Err(error("TLS peer closed"))
                } else {
                    Ok(None)
                };
            }
            if read_more {
                if self.incoming.len() >= TLS_BUFFER {
                    return Err(error("TLS input buffer exceeded"));
                }
                let mut bytes = vec![0; CHUNK.min(TLS_BUFFER - self.incoming.len())];
                let count = self.stream.read(&mut bytes).await?;
                if count == 0 {
                    return Err(error("TLS stream ended without close_notify"));
                }
                self.incoming.extend_from_slice(&bytes[..count]);
            }
        }
    }
}
impl<S> ErrorType for TlsStream<S> {
    type Error = Error;
}
impl<S: Read<Error = Error> + Write<Error = Error>> Read for TlsStream<S> {
    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Error> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.plaintext.is_empty() && !self.closed {
            self.drive(None).await?;
        }
        let length = buffer.len().min(self.plaintext.len());
        for byte in &mut buffer[..length] {
            *byte = self
                .plaintext
                .pop_front()
                .ok_or_else(|| error("missing TLS byte"))?;
        }
        Ok(length)
    }
}
impl<S: Read<Error = Error> + Write<Error = Error>> Write for TlsStream<S> {
    async fn write(&mut self, buffer: &[u8]) -> Result<usize, Error> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.drive(Some(buffer))
            .await?
            .ok_or_else(|| error("TLS write unavailable"))
    }
    async fn flush(&mut self) -> Result<(), Error> {
        self.stream.flush().await
    }
}

async fn perform(
    input: &[u8],
    mut call: impl FnMut(Value) -> Result<Value, String>,
    now: fn() -> Option<u64>,
) -> Result<Value, Error> {
    let request: Value = serde_json::from_slice(input).map_err(error)?;
    let inputs = &request["inputs"];
    let expected: u16 = match inputs.get("expected_status") {
        None => 200,
        Some(Value::String(value)) => value.parse().map_err(error)?,
        Some(value) => value
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| error("expected_status must be an unsigned decimal status"))?,
    };
    let url = inputs["url"]
        .as_str()
        .or_else(|| request["subject"]["value"].as_str())
        .ok_or_else(|| error("missing URL"))?;
    // Fragments are local client identifiers and never part of an HTTP target.
    let url = url.split_once('#').map_or(url, |(target, _)| target);
    let parsed = Url::parse(url).map_err(error)?;
    if !matches!(parsed.scheme(), UrlScheme::HTTP | UrlScheme::HTTPS) {
        return Err(error("HTTP(S) URL required"));
    }
    let config = call(json!({"kind":"proxy_config"})).map_err(error)?;
    let service_header = if let Some(service) = inputs["service"].as_str() {
        Some(call(json!({"kind":"gateway_header","service":service})).map_err(error)?)
    } else {
        None
    };
    let id = call(json!({"kind":"proxy_open"})).map_err(error)?["id"]
        .as_u64()
        .ok_or_else(|| error("proxy handle unavailable"))?;
    let mut stream = ProxyStream {
        id,
        call: &mut call,
    };
    let host = if parsed.host().contains(':') {
        format!("[{}]:{}", parsed.host(), parsed.port_or_default())
    } else {
        format!("{}:{}", parsed.host(), parsed.port_or_default())
    };
    let mut headers = vec![("Connection", "close")];
    if let Some(header) = service_header.as_ref() {
        let name = header["name"]
            .as_str()
            .ok_or_else(|| error("service header unavailable"))?;
        let value = header["value"]
            .as_str()
            .ok_or_else(|| error("service grant unavailable"))?;
        headers.push((name, value));
    }
    let mut buffer = vec![0; TLS_BUFFER];
    let status = if parsed.scheme() == UrlScheme::HTTPS {
        Request::connect(&host)
            .host(&host)
            .build()
            .write_header(&mut stream)
            .await
            .map_err(error)?;
        let response = Response::read(&mut stream, reqwless::request::Method::CONNECT, &mut buffer)
            .await
            .map_err(error)?;
        if response.status.0 != 200 {
            return Err(error(format!(
                "proxy CONNECT returned {}",
                response.status.0
            )));
        }
        drop(response);
        let mut roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let pem = config["ca_pem"]
            .as_str()
            .ok_or_else(|| error("proxy CA unavailable"))?;
        for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            roots.add(cert.map_err(error)?).map_err(error)?;
        }
        let tls = ClientConfig::builder_with_details(
            Arc::new(rustls::crypto::ring::default_provider()),
            Arc::new(Clock(now)),
        )
        .with_safe_default_protocol_versions()
        .map_err(error)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let stream = TlsStream::new(stream, tls, parsed.host())?;
        let mut connection = HttpConnection::Plain(stream);
        let response = connection
            .send(
                Request::get(parsed.path())
                    .host(&host)
                    .headers(&headers)
                    .build(),
                &mut buffer,
            )
            .await
            .map_err(error)?;
        response.status.0
    } else {
        let mut connection = HttpConnection::Plain(stream);
        let response = connection
            .send(
                Request::get(url).host(&host).headers(&headers).build(),
                &mut buffer,
            )
            .await
            .map_err(error)?;
        response.status.0
    };
    Ok(json!({"finding":{"kind":"finding","positive":status == expected}}))
}

/// Host callbacks are synchronous; this future has no external executor dependency.
pub fn check(
    input: &[u8],
    call: impl FnMut(Value) -> Result<Value, String>,
    now: fn() -> Option<u64>,
) -> Result<Value, String> {
    let mut future = pin!(perform(input, call, now));
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result.map_err(|e| e.to_string()),
        Poll::Pending => Err("proxy host call unexpectedly suspended".into()),
    }
}
