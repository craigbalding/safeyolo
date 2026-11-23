//! One bounded request over the executor's adopted socket or HTTPS transport.
use super::*;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use std::{os::unix::fs::MetadataExt, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};

pub(super) fn tls_configuration(pem: &str) -> Result<Arc<rustls::ClientConfig>, Error> {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(pem.as_bytes()) {
        roots.add(certificate?)?;
    }
    if roots.is_empty() {
        return Err("host HTTPS trust file contains no certificates".into());
    }
    Ok(Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth(),
    ))
}

async fn connect(binding: &Binding) -> Result<Box<dyn HostStream>, Error> {
    match &binding.endpoint {
        Endpoint::Https {
            host,
            port,
            certificate_pem,
        } => {
            let config = tls_configuration(certificate_pem)?;
            let stream = tokio::net::TcpStream::connect((host.as_str(), *port)).await?;
            let stream = tokio_rustls::TlsConnector::from(config)
                .connect(
                    rustls::pki_types::ServerName::try_from(host.clone())?,
                    stream,
                )
                .await?;
            Ok(Box::new(stream))
        }
        Endpoint::Unix {
            socket,
            executor_uid,
        } => {
            let canonical = socket.canonicalize()?;
            if canonical != *socket {
                return Err("host socket must use its canonical path".into());
            }
            // SAFETY: geteuid has no pointer arguments and reads current identity.
            let operator_uid = unsafe { libc::geteuid() };
            for path in canonical.ancestors().skip(1) {
                let meta = std::fs::symlink_metadata(path)?;
                if (meta.uid() != 0 && meta.uid() != *executor_uid && meta.uid() != operator_uid)
                    || meta.mode() & 0o022 != 0 && meta.mode() & 0o1000 == 0
                {
                    return Err("host socket parents permit replacement".into());
                }
            }
            let stream = tokio::net::UnixStream::connect(&canonical).await?;
            if stream.peer_cred()?.uid() != *executor_uid {
                return Err("host executor identity differs".into());
            }
            Ok(Box::new(stream))
        }
    }
}

trait HostStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> HostStream for T {}

pub(super) async fn send(
    binding: &Binding,
    verb: Verb,
    bytes: Vec<u8>,
    admit: impl FnOnce() -> Result<(), Error>,
) -> Result<Response, Error> {
    if bytes.len() > binding.request_bytes {
        return Err(refused(
            RefusalCode::Budget,
            "host request exceeds adopted transport limit",
        )
        .into());
    }
    let mut dispatched = false;
    let exchange = async {
        // Authenticate the adopted target before admission or writing signed bytes.
        let stream = connect(binding).await?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        let task = tokio::spawn(connection);
        // Abort the connection on a lost reply, cancellation or deadline. No
        // detached reader or automatic resend survives this exchange.
        struct Connection(tokio::task::JoinHandle<Result<(), hyper::Error>>);
        impl Drop for Connection {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        let _connection = Connection(task);
        let request = hyper::Request::builder()
            .method("POST")
            .uri(verb.path())
            .header("host", "host-executor.local")
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(bytes)))?;
        admit()?;
        dispatched = true;
        let response = sender.send_request(request).await?;
        if response.status() != hyper::StatusCode::OK {
            return Err("host transport returned a non-protocol status".into());
        }
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            if let Ok(data) = frame?.into_data() {
                if data.len() > binding.response_bytes.saturating_sub(bytes.len()) {
                    return Err("host response limit exceeded".into());
                }
                bytes.extend_from_slice(&data);
            }
        }
        Ok::<Response, Error>(serde_json::from_slice(&bytes)?)
    };
    let result = tokio::time::timeout(Duration::from_millis(binding.timeout_ms), exchange).await;
    match result {
        Ok(Err(error)) if !dispatched && error.downcast_ref::<Refusal>().is_none() => Err(refused(
            RefusalCode::Unavailable,
            "host executor transport unavailable before dispatch",
        )
        .into()),
        Err(_) if !dispatched => Err(refused(
            RefusalCode::Unavailable,
            "host executor connection deadline expired before dispatch",
        )
        .into()),
        Ok(result) => result,
        Err(error) => Err(error.into()),
    }
}
