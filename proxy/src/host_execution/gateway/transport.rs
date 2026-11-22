//! One bounded request over the executor's adopted local HTTP transport.
use super::*;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use std::{os::unix::fs::MetadataExt, time::Duration};

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
        // The endpoint is host policy, never a workload callback. Protect the
        // selected path against another local account replacing the executor.
        let canonical = binding.socket.canonicalize()?;
        if canonical != binding.socket {
            return Err("host socket must use its canonical path".into());
        }
        for path in canonical.ancestors().skip(1) {
            let meta = std::fs::symlink_metadata(path)?;
            if (meta.uid() != 0
                && meta.uid() != binding.executor_uid
                && meta.uid() != unsafe { libc::geteuid() })
                || meta.mode() & 0o022 != 0 && meta.mode() & 0o1000 == 0
            {
                return Err("host socket parents permit replacement".into());
            }
        }
        let stream = tokio::net::UnixStream::connect(&canonical).await?;
        if stream.peer_cred()?.uid() != binding.executor_uid {
            return Err("host executor identity differs".into());
        }
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        let task = tokio::spawn(async move { connection.await });
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
        Ok(serde_json::from_slice(&bytes)?)
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
