//! Ordinary HTTP observations for the operator's live view. This module never
//! reads a body or changes the request/response completion owners.

use std::sync::Arc;

use hyper::{Request, Response, Version};

use crate::{
    ConnectionIdentity, Runtime,
    traffic_view::{Exchange, RequestInfo},
};

use super::{Body, Destination};

/// Mark an actual upstream response so the outer local-response path cannot
/// replace its parser-owned status/body with a generated response observation.
#[derive(Clone)]
pub(super) struct Upstream;

pub(super) fn begin<B>(
    runtime: &Runtime,
    identity: &ConnectionIdentity,
    request_id: &str,
    request: &Request<B>,
    destination: &Destination,
) -> Option<Arc<Exchange>> {
    if request.method() == hyper::Method::CONNECT || crate::is_reserved(&destination.host) {
        return None;
    }
    let headers = if request.version() == Version::HTTP_2 {
        request
            .extensions()
            .get::<h2::ext::OriginalHeaderFields>()
            .map(|fields| pairs(fields.iter()))
    } else {
        request
            .extensions()
            .get::<hyper::ext::OriginalHeaderFields>()
            .map(|fields| pairs(fields.iter()))
    }
    .unwrap_or_else(|| header_map(request.headers()));
    Some(runtime.traffic_view.begin(RequestInfo {
        id: request_id.to_owned(),
        connection_id: identity.connection_id.clone(),
        agent: Some(identity.agent_id.clone()),
        method: request.method().to_string(),
        url: format!(
            "{}://{}{}",
            destination.scheme, destination.uri_authority, destination.path
        ),
        headers,
        started: crate::circuit_runtime::now(),
    }))
}

/// The live model retains header bytes reversibly as Latin-1 text; it does not
/// require UTF-8 header values or collapse repeated fields into a dictionary.
pub(super) fn pairs<'a>(
    fields: impl Iterator<Item = (&'a [u8], &'a [u8])>,
) -> Vec<(String, String)> {
    fields
        .map(|(name, value)| (header_text(name), header_text(value)))
        .collect()
}

fn header_text(bytes: &[u8]) -> String {
    let size = bytes
        .iter()
        .map(|byte| if byte.is_ascii() { 1 } else { 2 })
        .sum();
    let mut text = String::with_capacity(size);
    text.extend(bytes.iter().copied().map(char::from));
    text
}

pub(super) fn header_map(headers: &hyper::HeaderMap) -> Vec<(String, String)> {
    pairs(
        headers
            .iter()
            .map(|(name, value)| (name.as_str().as_bytes(), value.as_bytes())),
    )
}

pub(super) fn local_response(exchange: &Exchange, response: &Response<Body>) {
    exchange.response_head(response.status().as_u16(), header_map(response.headers()));
    // Local replies are already constructed, but their boxed body has no byte
    // borrow. Keep this capture limitation explicit instead of polling it.
    exchange.response_body(None);
    exchange.finish(None);
}

#[cfg(test)]
mod tests;
